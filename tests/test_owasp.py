"""Tests grouped by OWASP Top 10 (2021) category."""
import uuid
import pytest
from fastapi.testclient import TestClient
from shortener import app as appmod
from shortener.security import RateLimiter, validate_target

c = TestClient(appmod.app)
PW = "correct-horse-42battery"

def user():
    u = "u" + uuid.uuid4().hex[:10]
    assert c.post("/auth/register", json={"username": u, "password": PW}).status_code == 201
    t = c.post("/auth/login", json={"username": u, "password": PW}).json()["token"]
    return u, {"Authorization": f"Bearer {t}"}

# A01 Broken Access Control
def test_a01_idor_other_user_cannot_read_or_delete():
    _, a = user(); _, b = user()
    code = c.post("/links", json={"url": "https://example.com/a"}, headers=a).json()["code"]
    assert c.get(f"/links/{code}", headers=b).status_code == 404
    assert c.delete(f"/links/{code}", headers=b).status_code == 404
    assert c.get(f"/links/{code}", headers=a).status_code == 200

def test_a01_unauthenticated_create_rejected():
    assert c.post("/links", json={"url": "https://example.com"}).status_code == 401
    assert c.post("/links", json={"url": "https://example.com"}, headers={"Authorization": "Bearer forged"}).status_code == 401

# A02 Cryptographic Failures
def test_a02_passwords_and_tokens_stored_hashed():
    u, h = user()
    pw = appmod.q("SELECT pw FROM users WHERE username=?", (u,), one=True)[0]
    assert pw.startswith("scrypt$") and PW not in pw
    tok = h["Authorization"][7:]
    assert appmod.q("SELECT 1 FROM tokens WHERE hash=?", (tok,), one=True) is None

def test_a02_codes_unpredictable():
    _, h = user()
    codes = {c.post("/links", json={"url": "https://example.com"}, headers=h).json()["code"] for _ in range(50)}
    assert len(codes) == 50 and all(len(x) == 8 for x in codes)

# A03 Injection
@pytest.mark.parametrize("payload", ["' OR '1'='1", "x'; DROP TABLE links;--", "1 UNION SELECT pw FROM users"])
def test_a03_sqli_in_code_and_login(payload):
    assert c.get(f"/{payload}").status_code == 404
    r = c.post("/auth/login", json={"username": "admin", "password": payload})
    assert r.status_code in (401, 422)
    assert appmod.q("SELECT count(*) FROM links", one=True) is not None  # table still exists

# A04 Insecure Design: rate limiting
def test_a04_token_bucket_limits():
    rl = RateLimiter(capacity=3, rate=0.0001)
    assert [rl.allow("k")[0] for _ in range(5)] == [True, True, True, False, False]

def test_a04_api_returns_429_with_retry_after(monkeypatch):
    monkeypatch.setattr(appmod, "general", RateLimiter(capacity=5, rate=0.001))
    codes = [c.get("/nope1234").status_code for _ in range(8)]
    assert codes[:5] == [404] * 5 and codes[5:] == [429] * 3
    assert "Retry-After" in c.get("/nope1234").headers

# A05 Security Misconfiguration
def test_a05_security_headers_and_no_docs():
    r = c.get("/nope1234")
    for h in ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security", "Referrer-Policy"]:
        assert h in r.headers
    assert c.get("/docs").status_code == 404 and c.get("/openapi.json").status_code == 404

# A07 Identification & Authentication Failures
def test_a07_weak_password_rejected():
    assert c.post("/auth/register", json={"username": "weakling", "password": "password"}).status_code == 400

def test_a07_login_bruteforce_locked_and_no_enumeration():
    u, _ = user()
    r1 = c.post("/auth/login", json={"username": "nosuchuser", "password": "x"})
    r2 = c.post("/auth/login", json={"username": u, "password": "wrong"})
    assert r1.json() == r2.json() and r1.status_code == r2.status_code == 401
    codes = [c.post("/auth/login", json={"username": u, "password": "wrong"}).status_code for _ in range(6)]
    assert 429 in codes

# A10 SSRF / unsafe redirect targets
@pytest.mark.parametrize("url,ok", [("https://example.com/x", True), ("javascript:alert(1)", False), ("data:text/html,hi", False),
    ("http://127.0.0.1/admin", False), ("http://169.254.169.254/latest/meta-data/", False), ("http://10.0.0.5", False),
    ("http://localhost:8080", False), ("https://user:pass@example.com", False), ("https://sho.rt/abc", False),
    ("http://[::1]/", False), ("https://exa mple.com", False)])
def test_a10_target_validation(url, ok):
    assert (validate_target(url, "sho.rt") is None) == ok

def test_redirect_and_click_count():
    _, h = user()
    code = c.post("/links", json={"url": "https://example.com/z"}, headers=h).json()["code"]
    r = c.get(f"/{code}", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "https://example.com/z"
    assert c.get(f"/links/{code}", headers=h).json()["clicks"] == 1
