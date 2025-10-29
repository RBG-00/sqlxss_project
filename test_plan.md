# Test Plan — OWASP Juice Shop (Phase 1 → Phase 2)

Scope: Local lab — http://localhost:3000
Rules of Engagement: manual, non-destructive testing only; no DoS; no data exfiltration.

## Priority 1: /search?q (Reflected XSS candidate)
- Objective: confirm whether input q is reflected unescaped into HTML/DOM leading to XSS.
- Method: manual injection via browser + Burp intercept.
- Allowed payloads: benign/non-persistent (e.g. <svg/onload=alert(1)>). Avoid destructive testing.
- Tools: Browser, Burp.

## Priority 1: /rest/user/login (Input validation)
- Objective: check server-side validation for JSON fields; detect overly descriptive errors.
- Method: send malformed JSON / long strings to observe error handling.
- Allowed actions: observation only. No brute-force.
- Tools: curl, Burp.

## Priority 2: /product/:id (Parameter handling)
- Objective: detect injection or IDOR via path/query parameters.
- Method: vary id values and observe responses.
- Allowed actions: read-only requests, low-rate fuzzing.
- Tools: Burp, curl.

## Priority 2: /contact / feedback (Stored XSS candidate)
- Objective: verify if submitted content is persisted and displayed without escaping.
- Method: submit benign test message, then view pages where messages appear.
- Allowed actions: non-destructive stored checks only.
- Tools: Browser, Burp.

## Evidence & Logging
- Save raw requests to project/evidence/requests and responses to project/evidence/responses.
- Save screenshots to project/evidence/screenshots.
- Update project/evidence.log for each test step with timestamp, endpoint, action, and file refs.
EOF
