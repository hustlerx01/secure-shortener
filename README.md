# Secure URL Shortener API: FastAPI, auth, rate limiting, OWASP-mapped tests

> **Lab project.** A deliberately small codebase (about 250 lines) where every security control has a test named after its OWASP Top 10 (2021) category.

## Problem
URL shorteners look trivial but get abused all the time. Common problems:
- open redirects to `javascript:` URLs
- SSRF-style links to `169.254.169.254` cloud metadata
- sequential codes that let anyone enumerate private links
- IDOR on link stats
- credential stuffing on login
- bots creating links by the million

This API is built secure-by-default, and every control is proven by a test.

## Architecture
```mermaid
flowchart LR
  C[client] --> MW[middleware: token-bucket rate limit per IP + security headers]
  MW --> AU{route}
  AU -->|/auth/register| REG[password policy → scrypt hash]
  AU -->|/auth/login| LG[per user+IP login limiter → constant-work verify → random token, SHA-256 stored]
  AU -->|/links CRUD| BT[Bearer token check] --> VAL[URL validator: scheme, creds, private IPs, self-loop]
  VAL --> DB[(sqlite, parameterised SQL, owner-scoped queries)]
  AU -->|/{code}| RD[302 redirect + click count]
  RD --> DB
```

## Controls → OWASP Top 10 2021 → test
| OWASP | Control | Test |
|---|---|---|
| A01 Broken Access Control | All link queries use `WHERE owner=?`. Same 404 for missing and not-yours | `test_a01_idor_*`, `test_a01_unauthenticated_*` |
| A02 Cryptographic Failures | scrypt (n=2^14) password hashes. Tokens are 256-bit random and stored as SHA-256. Codes are 8 chars from `secrets` (~46 bits) | `test_a02_*` |
| A03 Injection | sqlite parameter binding everywhere, plus code-format check | `test_a03_sqli_*` (3 payloads) |
| A04 Insecure Design | Token bucket (30 burst, 1/s per IP), 429 + `Retry-After` | `test_a04_*` |
| A05 Misconfiguration | CSP, HSTS, XFO DENY, nosniff, no-referrer, no-store. `/docs` and `/openapi.json` disabled. No `server` header | `test_a05_*` |
| A07 Auth Failures | 12+ char password policy. 5 logins/min per user+IP. Identical error for unknown user vs wrong password. Dummy hash for constant work | `test_a07_*` |
| A10 SSRF / unsafe redirect | Only http/https. Blocks loopback, RFC 1918, link-local (metadata), IPv6 loopback, `user:pass@`, whitespace, self-loops. Optional DNS-resolution check | `test_a10_*` (11 cases) |

## Run
```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest -q
uvicorn shortener.app:app --port 8088 --no-server-header
python scripts/smoke.py http://127.0.0.1:8088      # live attack/smoke run
docker build -t secure-shortener . && docker run -p 8080:8080 -v shortdata:/data secure-shortener
```
API: `POST /auth/register`, `POST /auth/login` → `{token}`, `POST /links {url}` (Bearer), `GET/DELETE /links/{code}` (owner only), `GET /{code}` → 302.

## Results (actual runs, 2026-10-11)
- `pytest`: **24 passed** in 1.3 s.
- Live run against uvicorn (`results/live_smoke.json`):
  - create **201**, redirect **302** to the original URL
  - IDOR read as a second user → **404**
  - `http://169.254.169.254/latest/meta-data/` → **400** "private/internal address blocked"
  - `javascript:alert(document.cookie)` → **400**
  - SQLi in code path → **404**
  - Login brute force: **401 ×4 then 429 ×4** (the user's earlier successful login used one of the 5 tokens)
  - Burst of 40 requests in 0.03 s: **first 429 at request 12** (earlier smoke calls had used the rest of the 30-token bucket), 29 × 429 with `Retry-After: 1`
- Header scan of this running server with my `webvuln-scanner` project: see that project's `results/`.

## Limitations
- The rate limiter and login limiter are **in-memory and per-process**. With multiple workers or replicas, limits multiply. Production needs Redis or the API gateway.
- Behind a proxy, `request.client.host` is the proxy unless `--proxy-headers` and trusted `forwarded-allow-ips` are set correctly. Otherwise one bad client rate-limits everyone, or spoofed `X-Forwarded-For` bypasses the limit.
- DNS check (`RESOLVE_DNS=1`) is time-of-check only. A DNS-rebinding target can change after creation. That matters less for a redirector (the browser resolves, not the server), but a link-preview feature would need re-checking at fetch time.
- No malicious-URL reputation check (Safe Browsing / PhishTank), so phishing links can still be shortened.
- No token revocation or logout endpoint, no refresh tokens, no account lockout notification.
- Not pentested by a third party. Tests prove the controls I thought of, not the ones I missed.

## Sources
- OWASP Top 10 2021: https://owasp.org/Top10/
- OWASP ASVS 4.0.3 (V2 auth, V3 session, V5 validation): https://owasp.org/www-project-application-security-verification-standard/
- OWASP Unvalidated Redirects and Forwards Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP Password Storage Cheat Sheet (scrypt parameters): https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- NIST SP 800-63B (password length guidance): https://pages.nist.gov/800-63-3/sp800-63b.html
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
