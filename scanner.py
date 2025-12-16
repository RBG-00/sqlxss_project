#!/usr/bin/env python3
# scanner.py — Core Orchestrator
# Uses: sqli_part.py + xss_part.py
# Requirements: pip install requests beautifulsoup4

import argparse
import requests
import re
import time
import json as _json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
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

def request_with_timeout(method, url, params=None, data=None, headers=None, json_body=None):
    try:
        RATE_LIMITER.wait()
        if method.upper() == "POST":
            if json_body is not None:
                r = requests.post(
                    url, params=params, json=json_body, headers=headers,
                    timeout=TIMEOUT, allow_redirects=True
                )
            else:
                r = requests.post(
                    url, params=params, data=data, headers=headers,
                    timeout=TIMEOUT, allow_redirects=True
                )
        else:
            r = requests.get(
                url, params=params, headers=headers,
                timeout=TIMEOUT, allow_redirects=True
            )
        return r
    except Exception:
        return None

def baseline_response(method, url, params=None, data=None, headers=None, json_body=None):
    r = request_with_timeout(method, url, params=params, data=data, headers=headers, json_body=json_body)
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
    """
    Fingerprinting يعتمد على:
    - FINGERPRINT_RULES
    - + DB_ERROR_SIGNATURES الموجودة داخل sqli_part (error-based)
    """
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

    # Use DB error signatures from sqli_part to refine DB
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


# Payload sets (kept: DB-specific + default combined from both modules)
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
                json_body=None, json_key=None, base_text="", detected_type=None, fingerprint=None):

    if detected_type == "SQLi":
        ok = sqli_part.auto_verify_sqli(
            method=method,
            url=url,
            param_name=param_name,
            original_params=original_params,
            post_data=post_data,
            headers=headers,
            request_with_timeout=request_with_timeout,
            normalize_response=normalize_response,
            base_text=base_text,
            json_body=json_body,
            json_key=json_key
        )
        return {
            "verified": bool(ok),
            "evidence": "auto_verify_sqli " + ("succeeded" if ok else "failed"),
            "score_delta": 40 if ok else 0,
            "elapsed": 0.0
        }

    if detected_type == "XSS":
        ok = xss_part.auto_verify_xss(
            method=method,
            url=url,
            param_name=param_name,
            original_params=original_params,
            post_data=post_data,
            headers=headers,
            request_with_timeout=request_with_timeout,
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
    # Phase7 is single source of truth for SQLi classification. We only decide "SQLi-ish" for inclusion.
    if f.get("phase") in ("error", "blind", "time", "union"):
        return True
    vt = (f.get("vuln_type") or "").lower()
    return ("sqli" in vt) or (vt == "sqli") or ("sql" in vt and "xss" not in vt)

def _default_recommendations_for_non_sqli(f: dict):
    vt = (f.get("vuln_type") or "").strip().lower()
    if vt == "xss":
        return [
            "Output encoding (context-aware)",
            "Sanitize/validate user input",
            "Enable CSP (Content-Security-Policy)",
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
    # only include SQLi findings
    sqli_findings = [f for f in (findings or []) if _is_sqli_finding(f)]

    # enrich via Phase7 ONLY
    try:
        sqli_findings = sqli_part.enrich_sqli_findings_list(sqli_findings)
    except Exception as e:
        log(f"[DEBUG] enrich_sqli_findings_list failed: {e}")

    def esc(x):
        return _html.escape(str(x)) if x is not None else ""

    # small summary
    counts_by_type = {}
    counts_by_sev = {}
    for f in sqli_findings:
        rt = f.get("report_type") or "Unknown"
        sv = f.get("severity") or "Low"
        counts_by_type[rt] = counts_by_type.get(rt, 0) + 1
        counts_by_sev[sv] = counts_by_sev.get(sv, 0) + 1

    def badge_class(sev):
        s = (sev or "").lower()
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
    body {{
      font-family: Arial, sans-serif;
      background: #f6f7fb;
      margin: 0;
      color: #111;
    }}
    .wrap {{
      max-width: 1200px;
      margin: 24px auto;
      padding: 0 16px;
    }}
    .card {{
      background: #fff;
      border: 1px solid #e7e7ef;
      border-radius: 14px;
      box-shadow: 0 8px 22px rgba(0,0,0,0.06);
      padding: 16px;
      margin-bottom: 16px;
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: 22px;
    }}
    .meta {{
      color: #444;
      font-size: 13px;
      line-height: 1.5;
    }}
    .grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-top: 12px;
    }}
    @media (max-width: 900px) {{
      .grid {{ grid-template-columns: 1fr; }}
    }}
    ul {{
      margin: 6px 0 0;
      padding-left: 18px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      overflow: hidden;
      border-radius: 12px;
    }}
    th, td {{
      border-bottom: 1px solid #ececf4;
      padding: 10px;
      vertical-align: top;
      font-size: 13px;
    }}
    th {{
      text-align: left;
      background: #111827;
      color: #fff;
      position: sticky;
      top: 0;
      z-index: 1;
    }}
    tr:hover td {{
      background: #fafaff;
    }}
    .mono {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 12px;
    }}
    .badge {{
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      display: inline-block;
      border: 1px solid rgba(0,0,0,0.08);
    }}
    .sev-high {{ background: rgba(220, 38, 38, 0.12); color: #b91c1c; }}
    .sev-med  {{ background: rgba(245, 158, 11, 0.16); color: #b45309; }}
    .sev-low  {{ background: rgba(16, 185, 129, 0.16); color: #047857; }}
    .recs li {{ margin-bottom: 4px; }}
    .muted {{ color: #6b7280; }}
    .btn {{
      display:inline-block; padding:6px 10px; border-radius:10px;
      background:#111827; color:#fff; text-decoration:none; font-size:12px;
    }}
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

    # Enrich SQLi only via Phase7
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
    except Exception as e:
        log(f"[DEBUG] full-report enrich failed: {e}")

    def esc(x):
        return _html.escape(str(x)) if x is not None else ""

    def badge_class(sev):
        s = (sev or "").lower()
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
        vt  = esc(f.get("report_type") or f.get("vuln_type") or "Unknown")
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

    # Buckets
    sqli = [f for f in items if _is_sqli_finding(f)]
    xss  = [f for f in items if (f.get("vuln_type") or "").strip().upper() == "XSS"]
    heur = [f for f in items if (f.get("vuln_type") or "").strip().lower().startswith("possible")]

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
 .badge {{
   padding: 4px 10px; border-radius: 999px; font-size: 12px; display: inline-block;
   border: 1px solid rgba(0,0,0,0.08);
 }}
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
    <h1>Full Report (SQLi + XSS + Heuristics)</h1>
    <div class="meta">
      Generated at: <span class="mono">{esc(now_ts())}</span><br/>
      Total findings: <b>{len(items)}</b> | SQLi: <b>{len(sqli)}</b> | XSS: <b>{len(xss)}</b> | Heuristics: <b>{len(heur)}</b>
    </div>
    <div class="tabs" style="margin-top:10px">
      <a href="#sqli">SQLi</a>
      <a href="#xss">XSS</a>
      <a href="#heur">Heuristics</a>
    </div>
  </div>

  <div class="card" id="sqli">
    <h2>SQLi Findings (Phase 7 classification)</h2>
    <div style="overflow:auto; max-height:60vh;">
      <table>
        <thead><tr><th>URL</th><th>Param/Key</th><th>Type</th><th>Severity</th><th>Payload</th><th>Evidence</th><th>Recommendations</th><th>Open</th></tr></thead>
        <tbody>{''.join(row(f) for f in sqli) or '<tr><td colspan="8">No SQLi findings.</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  <div class="card" id="xss">
    <h2>XSS Findings</h2>
    <div style="overflow:auto; max-height:60vh;">
      <table>
        <thead><tr><th>URL</th><th>Param/Key</th><th>Type</th><th>Severity</th><th>Payload</th><th>Evidence</th><th>Recommendations</th><th>Open</th></tr></thead>
        <tbody>{''.join(row(f) for f in xss) or '<tr><td colspan="8">No XSS findings.</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  <div class="card" id="heur">
    <h2>Heuristics (Unclassified)</h2>
    <div style="overflow:auto; max-height:60vh;">
      <table>
        <thead><tr><th>URL</th><th>Param/Key</th><th>Type</th><th>Severity</th><th>Payload</th><th>Evidence</th><th>Recommendations</th><th>Open</th></tr></thead>
        <tbody>{''.join(row(f) for f in heur) or '<tr><td colspan="8">No heuristic findings.</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <div class="meta" style="color:#6b7280">
      Note: SQLi classification/severity/recommendations are generated by Phase 7 in <span class="mono">sqli_part.py</span> only.
      For XSS/Heuristics, recommendations are defaults for reporting convenience.
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
# Core single attempt (kept in scanner.py because Phase8 calls it)
# -------------------------
def _single_injection_attempt(method, url, param_name, original_params, base_text, base_status,
                              payload, post_data=None, headers=None, json_body=None, json_key=None,
                              verbose=False, fingerprint=None):

    # Build request
    if json_body is not None and json_key is not None:
        jb = deepcopy(json_body)
        jb[json_key] = payload
        r = request_with_timeout(method, url, headers=headers, json_body=jb)
        test_url = url
        injected_key = json_key
    else:
        params_copy = deepcopy(original_params) if original_params else {}
        injected_key = param_name if param_name is not None else "_scantest"
        params_copy[injected_key] = [payload]
        parsed = urlparse(url)
        query = urlencode({k: v[0] for k, v in params_copy.items()}, doseq=False)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

        if method.upper() == "POST":
            if post_data and injected_key in post_data:
                pd = deepcopy(post_data); pd[injected_key] = payload
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
            log(f"[DEBUG] Request failed for payload on {url}: param/key={injected_key}")
        return None

    text = r.text or ""
    status = r.status_code

    sqlerr = sqli_part.is_sql_error(text)
    reflected = (payload in text)
    len_ratio = length_change_ratio(normalize_response(base_text), normalize_response(text))

    vuln_type = None
    reasons = []
    phase = None  # only set phase for SQLi error-based here

    if sqlerr:
        vuln_type = "SQLi"
        phase = "error"  # Phase7 hook for Error-based SQLi
        reasons.append("SQL error pattern")

    # XSS if payload is one of base XSS payloads and reflected
    if reflected and payload in xss_part.XSS_PAYLOADS:
        vuln_type = "XSS"
        reasons.append("payload reflected")

    if len_ratio > LENGTH_DIFF_THRESHOLD and status == base_status and not vuln_type:
        vuln_type = "Possible Injection"
        reasons.append(f"response length changed by {len_ratio*100:.1f}%")

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
                detected_type=("SQLi" if vuln_type == "SQLi" else vuln_type),
                fingerprint=fingerprint
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

    msg = f"[VULN] {vuln_type} on {url} param/key '{finding['injected_param']}' payload: {payload} -- {finding['reason']} (score={score})"
    if finding["auto_verified"]:
        msg += " [AUTO-VERIFIED]"
    log(msg)

    return finding


def test_inject_all_params(method, url, params, payloads, base_text, base_status,
                           post_data=None, headers=None, verbose=False, fingerprint=None):
    """
    Inject the SAME payload into ALL parameters at once.
    """
    findings = []
    parsed = urlparse(url)

    for payload in payloads:
        params_all = {k: [payload] for k in params.keys()}
        query = urlencode({k: v[0] for k, v in params_all.items()}, doseq=False)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

        r = request_with_timeout("GET" if method.upper() == "GET" else "POST", new_url, data=post_data, headers=headers)
        if r is None:
            if verbose:
                log(f"[DEBUG] All-params request failed for payload: {payload}")
            continue

        text = r.text or ""
        status = r.status_code

        sqlerr = sqli_part.is_sql_error(text)
        reflected_xss = any(pl in text for pl in xss_part.XSS_PAYLOADS)
        len_ratio = length_change_ratio(normalize_response(base_text), normalize_response(text))

        if sqlerr or reflected_xss or (len_ratio > LENGTH_DIFF_THRESHOLD and status == base_status):
            if sqlerr:
                vuln_type = "SQLi"
                phase = "error"
            elif reflected_xss:
                vuln_type = "XSS"
                phase = None
            else:
                vuln_type = "Possible Multi-Param Injection"
                phase = None

            verify_result = {"verified": False, "evidence": "", "score_delta": 0, "elapsed": 0.0}
            if AUTO_VERIFY:
                try:
                    verify_result = verify_vuln(
                        method, url, None, params, post_data, headers,
                        base_text=base_text, detected_type=("SQLi" if vuln_type == "SQLi" else vuln_type), fingerprint=fingerprint
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

            findings.append(f)
            log(f"[VULN] Multi-param {vuln_type} on {url} payload: {payload} -- len_change={len_ratio:.2f} (score={score})")

    return findings


# -------------------------
# Crawling helpers (kept)
# -------------------------
JS_ENDPOINT_RE = re.compile(r'["\'](/rest/[a-zA-Z0-9_/\-?=&]+)["\']')

def is_same_domain(base_url, target_url):
    try:
        base_netloc = urlparse(base_url).netloc
        target_netloc = urlparse(target_url).netloc
        return base_netloc == target_netloc or target_netloc == ""
    except Exception:
        return False

def discover_endpoints_from_js(base_url, soup, headers=None):
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

        # Links
        for a in soup.find_all("a", href=True):
            href = a.get("href")
            if not href:
                continue
            full_url = add_dummy_param(urljoin(url, href))
            if is_same_domain(base_url, full_url) and full_url not in visited:
                queue.append((full_url, depth + 1))

        # GET forms
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

        # JS endpoints
        js_eps = discover_endpoints_from_js(base_url, soup, headers=headers)
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
# scan_target (clean + calls modules phases)
# -------------------------
def scan_target(
    url,
    method="GET",
    postdata_str=None,
    headers=None,
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
    dom_xss=False
):
    log(f"--- Scanning: {url} (method={method}) ---")

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Parse POST data
    post_data = None
    if postdata_str:
        post_data = {}
        for kv in postdata_str.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                post_data[k] = v

    # Parse JSON body
    json_body = None
    if json_str:
        try:
            json_body = json.loads(json_str)
        except Exception as e:
            log(f"[ERROR] bad --json for {url}: {e}")

    # Baseline
    base_status, base_text_raw, base_headers = baseline_response(
        method, url, headers=headers, json_body=json_body, data=post_data
    )
    if base_status is None:
        log(f"[ERROR] Baseline request failed: {url}")
        return []

    base_text = normalize_response(base_text_raw)

    # Fingerprint
    fingerprint = fingerprint_response(base_text_raw, base_headers)
    if verbose:
        log(f"[INFO] Fingerprint for {url}: {fingerprint}")

    # Active FP (SQL)
    try:
        if active_fp and params:
            db_guess, ev = sqli_part.active_db_fingerprint(
                method, url, params,
                request_with_timeout=request_with_timeout,
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

    # Payload selection
    if combined_payloads:
        payloads = combined_payloads
    elif payloads_categories:
        payloads = choose_payloads_from_categories(fingerprint, payloads_categories)
        if verbose:
            log(f"[*] Using categorized payloads ({len(payloads)})")
    else:
        payloads = choose_payloads(fingerprint)

    findings_total = []

    # Phase 10 DOM XSS
    try:
        if dom_xss and base_text_raw:
            ctype = (base_headers or {}).get("Content-Type", "")
            if "text/html" in ctype.lower() or "<html" in base_text_raw.lower():
                findings_total.extend(
                    xss_part.run_dom_xss_phase(
                        url=url,
                        base_html=base_text_raw,
                        TIMEOUT=TIMEOUT,
                        headers=headers,
                        fingerprint=fingerprint,
                        compute_score=compute_score,
                        log=log,
                        now_ts=now_ts,
                        verbose=verbose
                    )
                )
    except Exception as e:
        if verbose:
            log(f"[DEBUG] DOM XSS phase error on {url}: {e}")

    # Phase 1 Blind SQLi
    try:
        if method.upper() == "GET" and params:
            blind_phase = sqli_part.BlindBooleanSQLiPhase(
                request_with_timeout=request_with_timeout,
                normalize_response=normalize_response,
                now_ts=now_ts,
                compute_score=compute_score,
                log=log,
                retries=3,
                length_diff_ratio=0.15,
                similarity_threshold=0.97
            )
            findings_total.extend(blind_phase.run_for_url(method, url, headers=headers, fingerprint=fingerprint))
    except Exception as e:
        if verbose:
            log(f"[DEBUG] Blind SQLi phase error on {url}: {e}")

    # Phase 2 Time-based SQLi
    try:
        if time_sqli and params:
            findings_total.extend(
                sqli_part.run_time_based_sqli_phase(
                    method, url, params, headers, json_body, post_data,
                    fingerprint, time_delay, time_threshold, time_samples,
                    request_with_timeout=request_with_timeout,
                    compute_score=compute_score,
                    log=log,
                    now_ts=now_ts,
                    verbose=verbose
                )
            )
    except Exception as e:
        if verbose:
            log(f"[DEBUG] Time-based SQLi phase error on {url}: {e}")

    # Phase 3b UNION extract
    try:
        if union_extract and params:
            findings_total.extend(
                sqli_part.run_union_extraction_phase(
                    method, url, params, headers, fingerprint,
                    base_status=base_status,
                    base_text_raw=base_text_raw,
                    request_with_timeout=request_with_timeout,
                    normalize_response=normalize_response,
                    length_change_ratio=length_change_ratio,
                    compute_score=compute_score,
                    log=log,
                    now_ts=now_ts,
                    verbose=verbose
                )
            )
    except Exception as e:
        if verbose:
            log(f"[DEBUG] UNION phase error on {url}: {e}")

    # Phase 8 Context-aware XSS
    try:
        if xss_context and params:
            findings_total.extend(
                xss_part.run_context_aware_xss_phase(
                    method, url, params, headers, json_body, post_data,
                    base_status, base_text, verbose,
                    fingerprint,
                    request_with_timeout=request_with_timeout,
                    _single_injection_attempt=_single_injection_attempt,
                    log=log
                )
            )
    except Exception as e:
        if verbose:
            log(f"[DEBUG] Context-aware XSS phase error on {url}: {e}")

    # Phase 9 Advanced reflected XSS
    try:
        if xss_advanced and params:
            findings_total.extend(
                xss_part.run_advanced_reflected_xss_phase(
                    method, url, params, headers,
                    base_text_raw=base_text_raw,
                    fingerprint=fingerprint,
                    request_with_timeout=request_with_timeout,
                    compute_score=compute_score,
                    log=log,
                    now_ts=now_ts,
                    verbose=verbose
                )
            )
    except Exception as e:
        if verbose:
            log(f"[DEBUG] Advanced reflected XSS phase error on {url}: {e}")

    # Header variants
    header_variants = [headers] if headers is not None else [None]
    if headers_inject:
        header_variants = generate_header_variants(headers, payloads)

    # Build tasks
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
                    fingerprint=fingerprint
                )
            ))

    for hdr in header_variants:
        if json_body:
            for key in list(json_body.keys()):
                add_param_payload_tasks(hdr, None, {}, jb=json_body, jkey=key)
        else:
            if params:
                for pname in params.keys():
                    add_param_payload_tasks(hdr, pname, params)
                if inject_all_params_flag:
                    tasks.append((
                        "allparams",
                        dict(
                            method=method,
                            url=url,
                            params=params,
                            payloads=payloads,
                            base_text=base_text,
                            base_status=base_status,
                            post_data=post_data,
                            headers=hdr,
                            verbose=verbose,
                            fingerprint=fingerprint
                        )
                    ))
            else:
                test_param = "_scntest"
                add_param_payload_tasks(hdr, test_param, {test_param: ["1"]})

    # Execute tasks concurrently (Phase 3)
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

    # ✅ Phase 7 SQLi report
    parser.add_argument("--report-html", action="store_true", help="Generate SQLi HTML report (Phase 7)")
    parser.add_argument("--report-html-out", default="sqli_report.html", help="SQLi HTML report output file")

    # ✅ Full report (SQLi + XSS + Heuristics)
    parser.add_argument("--report-all-html", action="store_true", help="Generate FULL HTML report (SQLi + XSS + Heuristics)")
    parser.add_argument("--report-all-out", default="full_report.html", help="Full HTML report output file")

    # Concurrency/throttling
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--auto-verify", action="store_true")

    # Heuristics
    parser.add_argument("--len-threshold", type=float, default=0.30)

    # Crawling
    parser.add_argument("--crawl", action="store_true")
    parser.add_argument("--crawl-depth", type=int, default=2)
    parser.add_argument("--max-pages", type=int, default=100)
    parser.add_argument("--save-discovered", action="store_true")

    # SQLi phases
    parser.add_argument("--time-sqli", action="store_true")
    parser.add_argument("--time-delay", type=int, default=5)
    parser.add_argument("--time-threshold", type=float, default=4.0)
    parser.add_argument("--time-samples", type=int, default=3)
    parser.add_argument("--union-extract", action="store_true")
    parser.add_argument("--active-fp", action="store_true")

    # XSS phases
    parser.add_argument("--xss-context", action="store_true")
    parser.add_argument("--xss-advanced", action="store_true")
    parser.add_argument("--dom-xss", action="store_true")

    return parser


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

    # headers
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

    # clear report
    open(REPORT_FILE, "w", encoding="utf-8").close()

    # targets
    targets = []
    if args.url:
        if args.crawl:
            targets = crawl_site(args.url, max_depth=args.crawl_depth, max_pages=args.max_pages, headers=hdrs)
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
                dom_xss=args.dom_xss
            )
            all_findings.extend(f or [])
        except KeyboardInterrupt:
            print("Interrupted by user")
            break
        except Exception as e:
            log(f"[DEBUG] target error: {e}")

    elapsed = time.time() - start
    log(f"Scan finished in {elapsed:.2f}s. Findings: {len(all_findings)}")

    # ✅ Phase 7: enrich SQLi findings only (no SQLi classification in scanner.py)
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

    # write JSON report
    try:
        with open(REPORT_JSON, "w", encoding="utf-8") as jf:
            _json.dump({
                "generated_at": now_ts(),
                "targets_scanned": len(targets),
                "findings_count": len(all_findings),
                "findings": all_findings
            }, jf, indent=2, ensure_ascii=False)
        log(f"Structured JSON report saved to {REPORT_JSON}")
    except Exception as e:
        log(f"[ERROR] Could not write JSON report: {e}")

    # ✅ SQLi-only report (Phase 7)
    if REPORT_HTML_ENABLED:
        generate_sqli_html_report(all_findings, output_file=REPORT_HTML_FILE)

    # ✅ Full report (SQLi + XSS + Heuristics)
    if REPORT_ALL_HTML_ENABLED:
        generate_full_html_report(all_findings, output_file=REPORT_ALL_HTML_FILE)


if __name__ == "__main__":
    main()

