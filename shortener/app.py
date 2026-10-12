"""Secure URL shortener API. sqlite3 with parameterised queries only."""
import os, sqlite3, threading, time
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from .security import (RateLimiter, hash_password, verify_password, new_token, token_hash, new_code,
                       validate_target, PASSWORD_RE)

DB = os.environ.get("SHORTENER_DB", ":memory:")
SELF_HOST = os.environ.get("SHORTENER_HOST", "sho.rt")
_lock = threading.Lock()
conn = sqlite3.connect(DB, check_same_thread=False)
conn.executescript("""
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS links(code TEXT PRIMARY KEY, url TEXT NOT NULL, owner INTEGER NOT NULL, clicks INTEGER DEFAULT 0, created REAL);
""")

app = FastAPI(title="secure-shortener", docs_url=None, redoc_url=None, openapi_url=None)
general = RateLimiter(capacity=int(os.environ.get("RL_CAP", 30)), rate=float(os.environ.get("RL_RATE", 1)))
login_rl = RateLimiter(capacity=5, rate=5 / 60)  # 5 login attempts/min per username+IP
SEC_HEADERS = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
               "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'", "Cache-Control": "no-store",
               "Strict-Transport-Security": "max-age=63072000; includeSubDomains"}


@app.middleware("http")
async def guard(request: Request, call_next):
    ip = request.client.host if request.client else "?"
    ok, retry = general.allow(f"ip:{ip}")
    if not ok:
        resp = JSONResponse({"detail": "rate limit exceeded"}, status_code=429, headers={"Retry-After": str(int(retry) + 1)})
    else:
        resp = await call_next(request)
    for k, v in SEC_HEADERS.items(): resp.headers[k] = v
    if "server" in resp.headers: del resp.headers["server"]
    return resp


class Creds(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_]+$")
    password: str = Field(min_length=1, max_length=128)

class NewLink(BaseModel):
    url: str = Field(max_length=2048)


def q(sql, args=(), one=False):
    with _lock:
        cur = conn.execute(sql, args); conn.commit(); rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def current_user(authorization: str = Header(default="")) -> int:
    if not authorization.startswith("Bearer "): raise HTTPException(401, "missing bearer token")
    row = q("SELECT user_id, expires FROM tokens WHERE hash=?", (token_hash(authorization[7:]),), one=True)
    if not row or row[1] < time.time(): raise HTTPException(401, "invalid or expired token")
    return row[0]


@app.post("/auth/register", status_code=201)
def register(c: Creds):
    if not PASSWORD_RE.match(c.password): raise HTTPException(400, "password must be 12+ chars with letters and digits")
    try: q("INSERT INTO users(username, pw) VALUES(?,?)", (c.username, hash_password(c.password)))
    except sqlite3.IntegrityError: raise HTTPException(409, "username taken")
    return {"ok": True}


@app.post("/auth/login")
def login(c: Creds, request: Request):
    ok, retry = login_rl.allow(f"{c.username}|{request.client.host if request.client else '?'}")
    if not ok: raise HTTPException(429, "too many login attempts", headers={"Retry-After": str(int(retry) + 1)})
    row = q("SELECT id, pw FROM users WHERE username=?", (c.username,), one=True)
    dummy = "scrypt$" + "00" * 16 + "$" + "00" * 64
    valid = verify_password(c.password, row[1] if row else dummy)  # constant work even for unknown users
    if not (row and valid): raise HTTPException(401, "invalid credentials")  # same message: no user enumeration
    tok, h = new_token()
    q("INSERT INTO tokens VALUES(?,?,?)", (h, row[0], time.time() + 3600))
    return {"token": tok, "expires_in": 3600}


@app.post("/links", status_code=201)
def create(link: NewLink, uid: int = Depends(current_user)):
    err = validate_target(link.url, SELF_HOST, resolve=os.environ.get("RESOLVE_DNS") == "1")
    if err: raise HTTPException(400, f"rejected url: {err}")
    for _ in range(5):
        code = new_code()
        try:
            q("INSERT INTO links(code,url,owner,created) VALUES(?,?,?,?)", (code, link.url, uid, time.time())); break
        except sqlite3.IntegrityError: continue
    return {"code": code, "short": f"https://{SELF_HOST}/{code}"}


@app.get("/links/{code}")
def stats(code: str, uid: int = Depends(current_user)):
    row = q("SELECT url, clicks FROM links WHERE code=? AND owner=?", (code, uid), one=True)
    if not row: raise HTTPException(404, "not found")  # same 404 for missing and not-yours (no IDOR oracle)
    return {"code": code, "url": row[0], "clicks": row[1]}


@app.delete("/links/{code}", status_code=204)
def delete(code: str, uid: int = Depends(current_user)):
    with _lock:
        cur = conn.execute("DELETE FROM links WHERE code=? AND owner=?", (code, uid)); conn.commit()
    if cur.rowcount == 0: raise HTTPException(404, "not found")


@app.get("/{code}")
def follow(code: str):
    if not (4 <= len(code) <= 16 and code.isalnum()): raise HTTPException(404, "not found")
    row = q("SELECT url FROM links WHERE code=?", (code,), one=True)
    if not row: raise HTTPException(404, "not found")
    q("UPDATE links SET clicks = clicks + 1 WHERE code=?", (code,))
    return RedirectResponse(row[0], status_code=302)
