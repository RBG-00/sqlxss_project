#!/usr/bin/env python3
# scanner.py — Phases 1+2 + Phase 3 (Concurrency & Throttling + Auto-Verify)
# Requirements: pip install requests

import argparse
import requests
import re
import time
import json as _json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from copy import deepcopy
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# --- Default Config / payloads ---
SQL_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "'; --", " OR 1=1--"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

SQL_ERR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"syntax error.*mysql",
    r"pg_query\(",
]
SQL_ERR_RE = re.compile("|".join(SQL_ERR_PATTERNS), re.IGNORECASE)

# Will be overridden by args
TIMEOUT = 10
REPORT_FILE = "report.txt"
REPORT_JSON = "report.json"
AUTO_VERIFY = False

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
    r = request_with_timeout(method, url, params=params, data=data, headers=headers, json_body=json_body)
    if not r:
        return None, None
    return r.status_code, r.text or ""

def length_change_ratio(base_text, new_text):
    if base_text is None or new_text is None:
        return 0.0
    b = len(base_text); n = len(new_text)
    if b == 0:
        return abs(n)
    return abs(n - b) / b

# --- Auto-verification helpers ---
def auto_verify_sqli(method, url, param_name, original_params, post_data, headers,
                     json_body=None, json_key=None, base_text=""):
    """
    Boolean-based check by diffing true/false conditions.
    """
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
    len_diff = abs(len(r_true.text or "") - len(r_false.text or ""))
    if len_diff > max(30, int(len(base_text or "") * 0.03)) or (r_true.text != r_false.text) or (r_true.status_code != r_false.status_code):
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
        for pl in payloads:
            hcopy = deepcopy(base_headers)
            hcopy[h] = pl
            variants.append(hcopy)
    return variants

# --- Core testing logic (single injection attempt) ---
def _single_injection_attempt(method, url, param_name, original_params, base_text, base_status,
                              payload, post_data=None, headers=None, json_body=None, json_key=None, verbose=False):
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
    len_ratio = length_change_ratio(base_text, text)

    vuln_type = None
    reason = []
    if sqlerr:
        vuln_type = "SQLi"
        reason.append("SQL error pattern")
    if reflected and any(payload == x for x in XSS_PAYLOADS):
        vuln_type = "XSS"
        reason.append("payload reflected")
    if len_ratio > 0.30 and status == base_status and not vuln_type:
        vuln_type = "Possible Injection"
        reason.append(f"response length changed by {len_ratio*100:.1f}%")

    finding = None
    if vuln_type:
        verified = False
        if AUTO_VERIFY:
            try:
                if vuln_type == "SQLi":
                    verified = auto_verify_sqli(method, url, param_name, original_params, post_data, headers,
                                                json_body=json_body, json_key=json_key, base_text=base_text)
                elif vuln_type == "XSS":
                    verified = auto_verify_xss(method, url, param_name, original_params, post_data, headers,
                                               json_body=json_body, json_key=json_key)
                else:
                    if "reflected" in " ".join(reason):
                        verified = auto_verify_xss(method, url, param_name, original_params, post_data, headers,
                                                   json_body=json_body, json_key=json_key)
            except Exception:
                verified = False

        finding = {
            "timestamp": now_ts(),
            "url": url,
            "test_url": test_url,
            "method": method.upper(),
            "injected_param": json_key if json_key else param_name,
            "payload": payload,
            "vuln_type": vuln_type,
            "reason": "; ".join(reason),
            "status": status,
            "auto_verified": bool(verified)
        }
        msg = f"[VULN] {vuln_type} on {url} param/key '{finding['injected_param']}' payload: {payload} -- {finding['reason']}"
        if finding["auto_verified"]:
            msg += " [AUTO-VERIFIED]"
        log(msg)
    return finding

def test_inject_all_params(method, url, params, payloads, base_text, base_status, post_data=None, headers=None, verbose=False):
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
        len_ratio = length_change_ratio(base_text, text)
        if sqlerr or (reflected and any(pl in XSS_PAYLOADS for pl in payloads)) or (len_ratio > 0.30 and status == base_status):
            finding = {
                "timestamp": now_ts(),
                "url": url,
                "test_url": new_url,
                "method": method.upper(),
                "injected_param": ",".join(params.keys()),
                "payload": payload,
                "vuln_type": "Possible Multi-Param Injection" if not sqlerr else "SQLi",
                "reason": f"all params set to payload; sqlerr={sqlerr}; len_change={len_ratio:.2f}",
                "status": status,
                "auto_verified": False
            }
            findings.append(finding)
            log(f"[VULN] Multi-param {finding['vuln_type']} on {url} payload: {payload} -- {finding['reason']}")
    return findings

# --- High level scanning for a single target (Phase 3 concurrency inside) ---
def scan_target(url, method="GET", postdata_str=None, headers=None, json_str=None,
                headers_inject=False, inject_all_params_flag=False, combined_payloads=None,
                verbose=False, threads=1):
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
            import json
            json_body = json.loads(json_str)
        except Exception as e:
            log(f"[ERROR] bad --json for {url}: {e}")

    base_status, base_text = baseline_response(method, url, headers=headers, json_body=json_body, data=post_data)
    if base_status is None:
        log(f"[ERROR] Baseline request failed: {url}")
        return []

    payloads = combined_payloads or (SQL_PAYLOADS + XSS_PAYLOADS)

    findings_total = []
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
                post_data=post_data, headers=hdr, json_body=jb, json_key=jkey, verbose=verbose
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
                        base_text=base_text, base_status=base_status, post_data=post_data, headers=hdr, verbose=verbose
                    )) )
            else:
                test_param = "_scantest"
                add_param_payload_tasks(hdr, test_param, {test_param: ["1"]})

    # Execute tasks concurrently (Phase 3)
    max_workers = max(1, int(threads or 1))
    if max_workers == 1:
        # sequential
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

def build_argparser():
    parser = argparse.ArgumentParser(description="MVP SQLi/XSS scanner - Phase 2+3 enhancements")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", "-u", help="Target URL to scan")
    group.add_argument("--file", help="File with list of target URLs (one per line)")
    parser.add_argument("--method", "-m", choices=["GET","POST"], default="GET", help="HTTP method (default GET)")
    parser.add_argument("--postdata", default=None, help="POST data as key=value&k2=v2")
    parser.add_argument("--json", default=None, help='POST JSON body as a JSON string, e.g. \'{"q":"test"}\'')
    parser.add_argument("--headers", default=None, help="Extra headers as key1:val1|key2:val2")
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout seconds')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--headers-inject', action='store_true', help='Try payloads in headers (User-Agent, Referer, X-Forwarded-For)')
    parser.add_argument('--inject-all-params', dest='inject_all_params', action='store_true', help='Inject payloads into all parameters of a request')
    parser.add_argument('--payloads', type=str, help='Path to payload file (one payload per line). If omitted, uses built-in lists.')
    parser.add_argument('--report-json', default='report.json', help='Path to structured JSON report')
    parser.add_argument('--report-txt', default='report.txt', help='Path to human-readable report')

    # Phase 3 flags:
    parser.add_argument('--threads', type=int, default=1, help='Concurrency: worker threads (>=1). Applies inside each target.')
    parser.add_argument('--delay', type=float, default=0.0, help='Global delay (seconds) between requests for throttling')
    parser.add_argument('--auto-verify', action='store_true', help='Run simple auto-verification (SQLi boolean, XSS token reflect)')
    return parser

def main():
    global TIMEOUT, REPORT_FILE, REPORT_JSON, AUTO_VERIFY, RATE_LIMITER
    parser = build_argparser()
    args = parser.parse_args()

    TIMEOUT = int(args.timeout)
    REPORT_FILE = args.report_txt
    REPORT_JSON = args.report_json
    AUTO_VERIFY = bool(args.auto_verify)
    RATE_LIMITER = RateLimiter(args.delay or 0.0)

    # prepare headers
    hdrs = {}
    if args.headers:
        for kv in args.headers.split("|"):
            if ":" in kv:
                k, v = kv.split(":", 1)
                hdrs[k.strip()] = v.strip()

    # payloads loading
    combined_payloads = None
    if args.payloads:
        pl = load_payloads_file(args.payloads)
        if pl:
            combined_payloads = pl
            if args.verbose:
                log(f"[*] Loaded {len(pl)} payloads from {args.payloads}")
    if combined_payloads is None:
        combined_payloads = SQL_PAYLOADS + XSS_PAYLOADS

    # clear report files
    open(REPORT_FILE, "w", encoding="utf-8").close()

    # targets
    targets = []
    if args.url:
        targets = [args.url]
    else:
        targets = load_targets_from_file(args.file)

    all_findings = []
    start = time.time()

    # Phase 3: Concurrency across targets too (uses same --threads for simplicity)
    if args.threads and args.threads > 1 and len(targets) > 1:
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = []
            for t in targets:
                futs.append(ex.submit(
                    scan_target, t, method=args.method, postdata_str=args.postdata, headers=hdrs, json_str=args.json,
                    headers_inject=args.headers_inject, inject_all_params_flag=args.inject_all_params,
                    combined_payloads=combined_payloads, verbose=args.verbose, threads=args.threads
                ))
            for f in as_completed(futs):
                try:
                    all_findings.extend(f.result() or [])
                except KeyboardInterrupt:
                    log("Interrupted by user")
                    break
                except Exception as e:
                    if args.verbose:
                        log(f"[DEBUG] target error: {e}")
    else:
        for t in targets:
            try:
                f = scan_target(t, method=args.method, postdata_str=args.postdata, headers=hdrs, json_str=args.json,
                                headers_inject=args.headers_inject, inject_all_params_flag=args.inject_all_params,
                                combined_payloads=combined_payloads, verbose=args.verbose, threads=args.threads)
                all_findings.extend(f)
            except KeyboardInterrupt:
                print("Interrupted by user")
                break

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
