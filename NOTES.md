# Interview talking points: Secure URL shortener

1. **Threat model first.** A shortener's risks: open redirect/phishing, enumeration of private links, IDOR on stats, credential stuffing, bot abuse, and internal targets. Each one maps to an OWASP Top 10 category and a named test.
2. **IDOR done right.** Every query is scoped `WHERE code=? AND owner=?`, and "not yours" returns the same 404 as "doesn't exist", so there's no oracle. Proven with two users in `test_a01_idor_*`.
3. **Unguessable codes.** 8 chars from a 56-symbol alphabet via `secrets` is about 46 bits. Sequential or base62(id) codes let anyone crawl every link.
4. **Token storage.** Bearer tokens are 256-bit random and only their SHA-256 is stored, so a DB leak doesn't give session takeover. Passwords use scrypt per the OWASP cheat sheet, compared with `hmac.compare_digest`.
5. **No user enumeration.** Same message for an unknown user and a wrong password, *and* I verify against a dummy hash so response timing doesn't leak which usernames exist.
6. **Rate limiting.** Token bucket: burst 30, refill 1/s per IP. A separate limiter on login per user+IP: 5/min. The live run showed 429 + `Retry-After`. I know it's per-process, so in production it moves to Redis or the gateway, and I'd explain the X-Forwarded-For trust problem.
7. **Redirect target validation.** Only http/https. Block `javascript:`/`data:`, `user:pass@` (phishing trick), loopback, RFC 1918, link-local 169.254.169.254, and self-loops. I know the limit: DNS rebinding and phishing reputation need extra layers.
8. **Proof, not claims.** 24 tests, a live smoke script in CI, and the headers checked by my own web scanner project.
