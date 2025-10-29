# Targets map — OWASP Juice Shop (Local)
Base URL: http://localhost:3000
Generated: 2025-10-28T00:00:00Z

## Endpoint: /
- Path: /
- Method: GET
- Notes: Homepage. Loads main scripts and links to product pages, search, REST APIs.

## Endpoint: /search
- Path: /search
- Method: GET
- Notes: Query param `q` rendered in results area — candidate for reflected XSS.

## Endpoint: /product/:id
- Path: /product/1 (example)
- Method: GET
- Notes: Product id appears in page and used in API calls.

## Endpoint: /rest/user/login
- Path: /rest/user/login
- Method: POST (application/json)
- Notes: Authentication API — returns JWT on success. Sensitive: do not brute-force.
EOF
