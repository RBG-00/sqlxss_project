#!/usr/bin/env python3
"""
MVP scanner (updated):
- supports GET and POST form-data (existing)
- supports POST JSON bodies via --json '{"q":"test"}' and will inject payloads into top-level keys
- writes human report.txt and structured report.json
"""

import argparse
import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from copy import deepcopy
import sys
import time
import json as _json
from datetime import datetime, timezone

# --- Config / payloads ---
SQL_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "'; --", " OR 1=1--"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
SQL_ERR_PATTERNS = [
    r"you have an error in your sql syntax", r"warning: mysql",
    r"unclosed quotation mark after the character string", r"syntax error.*mysql",
    r"pg_query\(", r"mysqli_fetch", r"sql syntax.*mysql", r"odbc", r"ora-"
]
SQL_ERR_RE = re.compile("|".join(SQL_ERR_PATTERNS), re.IGNORECASE)

TIMEOUT = 10
REPORT_FILE = "report.txt"
REPORT_JSON = "report.json"

# --- Helpers ---
def now_ts():
    return datetime.now(timezone.utc).isoformat()

def log(msg):
    print(msg)
    with open(REPORT_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def request_with_timeout(method, url, params=None, data=None, headers=None, json_body=None):
    try:
        if method.upper() == "POST":
            if json_body is not None:
                r = requests.post(url, json=json_body, params=params, headers=headers, timeout=TIMEOUT, allow_redirects=True)
            else:
                r = requests.post(url, data=data, params=params, headers=headers, timeout=TIMEOUT, allow_redirects=True)
        else:
            r = requests.get(url, params=params, headers=headers, timeout=TIMEOUT, allow_redirects=True)
        return r
    except Exception as e:
        return None

def baseline_response(method, url, params=None, data=None, headers=None, json_body=None):
    r = request_with_timeout(method, url, params=params, data=data, headers=headers, json_body=json_body)
    if r is None:
        return None
    return r.status_code, r.text

def is_sql_error(text):
    return bool(SQL_ERR_RE.search(text or ""))

def is_reflected(payload, text):
    if not text:
        return False
    return payload in text

def length_change_ratio(base_text, new_text):
    if base_text is None or new_text is None:
        return 0.0
    b = len(base_text)
    n = len(new_text)
    if b == 0:
        return abs(n)
    return abs(n - b) / b

# --- Core testing logic ---
def inject_and_test(method, url, param_name, original_params, base_text, base_status, post_data=None, headers=None, json_body=None, json_key=None):
    findings = []
    # choose proper payload sets based on param_name or both
    for payload in (SQL_PAYLOADS + XSS_PAYLOADS):
        # Build request depending on JSON or form/GET
        if json_body is not None and json_key is not None:
            # inject into JSON payload (top-level key)
            jb = deepcopy(json_body)
            jb[json_key] = payload
            r = request_with_timeout(method, url, headers=headers, json_body=jb)
            test_url = url  # JSON requests keep URL same
        else:
            # inject into query params or form-data
            params_copy = deepcopy(original_params)
            params_copy[param_name] = [payload]  # parse_qs style lists
            parsed = urlparse(url)
            query = urlencode({k: v[0] for k, v in params_copy.items()}, doseq=False)
            new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
            if method.upper() == "POST":
                # inject into post_data if provided else into query
                if post_data and param_name in post_data:
                    pd = deepcopy(post_data)
                    pd[param_name] = payload
                    r = request_with_timeout("POST", url, data=pd, headers=headers)
                    test_url = url
                else:
                    # fallback to new_url GET-like injection or POST with same data
                    r = request_with_timeout("GET", new_url, headers=headers) if method.upper()=="GET" else request_with_timeout("POST", new_url, data=post_data, headers=headers)
                    test_url = new_url
            else:
                r = request_with_timeout("GET", new_url, headers=headers)
                test_url = new_url

        if r is None:
            continue

        text = r.text
        status = r.status_code

        # heuristics
        sqlerr = is_sql_error(text)
        reflected = is_reflected(payload, text)
        len_ratio = length_change_ratio(base_text, text)

        vuln_type = None
        reason = []
        if sqlerr:
            vuln_type = "SQLi"
            reason.append("SQL error pattern detected")
        if reflected and payload in XSS_PAYLOADS:
            vuln_type = vuln_type or "XSS"
            reason.append("payload reflected in response")
        if len_ratio > 0.30 and status == base_status:
            vuln_type = vuln_type or "Possible Injection"
            reason.append(f"response length changed by {len_ratio*100:.1f}%")

        if vuln_type:
            finding = {
                "timestamp": now_ts(),
                "url": url,
                "test_url": test_url,
                "method": method.upper(),
                "injected_param": json_key if json_key is not None else param_name,
                "payload": payload,
                "vuln_type": vuln_type,
                "reason": "; ".join(reason),
                "status": status
            }
            findings.append(finding)
            msg = f"[VULN] {finding['vuln_type']} on {finding['url']} param/key '{finding['injected_param']}' payload: {payload} -- {finding['reason']}"
            log(msg)
    return findings

# --- High level scanning for a single target ---
def scan_target(url, method="GET", postdata_str=None, headers=None, json_str=None):
    log(f"--- Scanning: {url} (method={method}) ---")
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    # build base POST data dict if provided
    post_data = None
    if method.upper() == "POST" and postdata_str:
        post_data = {}
        for kv in postdata_str.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                post_data[k] = v
            else:
                post_data[kv] = ""

    # parse JSON if provided
    json_body = None
    if method.upper() == "POST" and json_str:
        try:
            json_body = _json.loads(json_str)
            if not isinstance(json_body, dict):
                log("[ERROR] Only top-level JSON object is supported for --json")
                json_body = None
        except Exception as e:
            log(f"[ERROR] Invalid JSON provided to --json: {e}")
            json_body = None

    # baseline request (original)
    base_resp = baseline_response(method, url, params=None if method.upper()=="POST" else None, data=post_data, headers=headers, json_body=json_body)
    if base_resp is None:
        log(f"[ERROR] Could not reach {url}")
        return []
    base_status, base_text = base_resp

    findings_total = []
    # If JSON body provided, test each top-level key
    if json_body:
        for key in list(json_body.keys()):
            findings = inject_and_test(method, url, None, {}, base_text, base_status, post_data=post_data, headers=headers, json_body=json_body, json_key=key)
            findings_total.extend(findings)
    else:
        # If there are query params, test each
        if params:
            for pname in params.keys():
                findings = inject_and_test(method, url, pname, params, base_text, base_status, post_data=post_data, headers=headers)
                findings_total.extend(findings)
        else:
            # No query params: attempt a single param injection by appending a test param
            test_param = "_scantest"
            params_copy = {test_param: ["1"]}
            findings = inject_and_test(method, url, test_param, params_copy, base_text, base_status, post_data=post_data, headers=headers)
            findings_total.extend(findings)

    if not findings_total:
        log(f"[OK] No issues detected (basic heuristics) for: {url}")
    log("")  # newline
    return findings_total

# --- CLI and orchestration ---
def load_targets_from_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
        return lines
    except Exception as e:
        print("Error reading file:", e)
        return []

def main():
    parser = argparse.ArgumentParser(description="MVP SQLi/XSS scanner (basic heuristics) with JSON support.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Target URL to scan")
    group.add_argument("--file", help="File with list of target URLs (one per line)")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"], help="HTTP method to use (default GET)")
    parser.add_argument("--postdata", default=None, help="POST data as key=value&k2=v2 (used when --method POST)")
    parser.add_argument("--json", default=None, help="POST JSON body as a JSON string, e.g. '{\"q\":\"test\"}'")
    parser.add_argument("--headers", default=None, help="Extra headers as key1:val1|key2:val2")
    args = parser.parse_args()

    # prepare headers
    hdrs = {}
    if args.headers:
        for kv in args.headers.split("|"):
            if ":" in kv:
                k, v = kv.split(":", 1)
                hdrs[k.strip()] = v.strip()

    # clear report files
    open(REPORT_FILE, "w", encoding="utf-8").close()
    # JSON report will be written at the end
    all_findings = []

    targets = []
    if args.url:
        targets = [args.url.strip()]
    else:
        targets = load_targets_from_file(args.file)

    start = time.time()
    for t in targets:
        try:
            f = scan_target(t, method=args.method, postdata_str=args.postdata, headers=hdrs, json_str=args.json)
            all_findings.extend(f)
        except KeyboardInterrupt:
            print("Interrupted by user")
            break
        except Exception as e:
            log(f"[ERROR] Exception scanning {t}: {e}")

    duration = time.time() - start
    log(f"--- Done. Scanned {len(targets)} target(s) in {duration:.1f}s. Findings: {len(all_findings)} ---")

    # write structured JSON report
    try:
        with open(REPORT_JSON, "w", encoding="utf-8") as jf:
            _json.dump({"generated_at": now_ts(), "targets_scanned": len(targets), "findings_count": len(all_findings), "findings": all_findings}, jf, indent=2)
        if all_findings:
            log(f"Structured JSON report saved to {REPORT_JSON}")
    except Exception as e:
        log(f"[ERROR] Could not write JSON report: {e}")

if __name__ == "__main__":
    main()
