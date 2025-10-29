# Input points — OWASP Juice Shop (generated)

### /search?q
- Path: /search
- Method: GET
- Parameter: q (query string)
- Type: text
- Reflected in response: YES (appears in results area / DOM)
- Notes: Candidate for reflected XSS; client-side DOM updates also occur.

### /product/:id
- Path: /product/1
- Method: GET
- Parameter: id (path param)
- Type: numeric / alphanumeric
- Reflected in response: PARTIAL (id/name shown)
- Notes: Check for parameter tampering, IDOR or injection via numeric param.

### /rest/user/login (JSON)
- Path: /rest/user/login
- Method: POST
- Parameters: email (string), password (string) in JSON body
- Type: JSON
- Reflected: NO (returns token) — but validate input handling
- Notes: Only non-destructive validation checks allowed.

### /rest/products (API search/filter)
- Path: /rest/products or /api/search endpoints
- Method: GET / POST
- Parameters: q, filter, category
- Type: query / JSON
- Reflected: POSSIBLE in JSON responses or in subsequent rendered HTML
- Notes: inspect raw JSON and the UI rendering.

### /contact (feedback)
- Path: /contact (or similar)
- Method: POST (form)
- Parameters: name, email, message
- Type: form-data
- Reflected: POSSIBLE (confirmation or admin view)
- Notes: candidate for stored XSS if persisted.
EOF
