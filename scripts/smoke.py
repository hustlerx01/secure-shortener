"""Live end-to-end smoke/attack run against a running server: python scripts/smoke.py http://127.0.0.1:8088"""
import json, sys, time, uuid, httpx
B = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8088"
c = httpx.Client(base_url=B, timeout=10); out = {}
def reg(): 
    u = "u" + uuid.uuid4().hex[:8]; pw = "correct-horse-42battery"
    c.post("/auth/register", json={"username": u, "password": pw})
    return u, {"Authorization": "Bearer " + c.post("/auth/login", json={"username": u, "password": pw}).json()["token"]}
ua, a = reg(); ub, b = reg()
r = c.post("/links", json={"url": "https://owasp.org/Top10/"}, headers=a); code = r.json()["code"]
out["create"] = r.status_code
out["redirect"] = [c.get(f"/{code}").status_code, c.get(f"/{code}").headers.get("location")]
out["idor_read_as_other_user"] = c.get(f"/links/{code}", headers=b).status_code
out["ssrf_metadata"] = c.post("/links", json={"url": "http://169.254.169.254/latest/meta-data/"}, headers=a).json()
out["js_scheme"] = c.post("/links", json={"url": "javascript:alert(document.cookie)"}, headers=a).json()
out["sqli_code"] = c.get("/' OR '1'='1").status_code
out["login_bruteforce_statuses"] = [c.post("/auth/login", json={"username": ua, "password": f"guess{i}"}).status_code for i in range(8)]
t0 = time.time(); burst = [c.get("/doesnotexist").status_code for _ in range(40)]
out["burst_40_requests"] = {"404": burst.count(404), "429": burst.count(429), "first_429_at": burst.index(429) + 1 if 429 in burst else None, "seconds": round(time.time() - t0, 2)}
out["headers_sample"] = {k: v for k, v in c.get("/doesnotexist").headers.items() if k.lower() in ("content-security-policy", "x-frame-options", "strict-transport-security", "retry-after", "server")}
print(json.dumps(out, indent=2))
