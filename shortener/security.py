import hashlib, hmac, ipaddress, os, re, secrets, socket, threading, time
from urllib.parse import urlsplit

def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${h.hex()}"

def verify_password(pw: str, stored: str) -> bool:
    _, salt, h = stored.split("$")
    cand = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
    return hmac.compare_digest(cand.hex(), h)

def new_token() -> tuple[str, str]:
    t = secrets.token_urlsafe(32)
    return t, hashlib.sha256(t.encode()).hexdigest()  # only the hash is stored

token_hash = lambda t: hashlib.sha256(t.encode()).hexdigest()
ALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
new_code = lambda n=8: "".join(secrets.choice(ALPHABET) for _ in range(n))  # ~46 bits, not sequential
PASSWORD_RE = re.compile(r"^(?=.*[A-Za-z])(?=.*\d).{12,128}$")

BLOCKED_HOSTS = {"localhost", "metadata.google.internal"}

def validate_target(url: str, self_host: str | None = None, resolve: bool = False) -> str | None:
    """Return error string or None. Blocks non-http(s), credentials in URL, private/loopback/link-local targets, self-loops."""
    if len(url) > 2048: return "url too long"
    if any(c in url for c in "\r\n\t "): return "whitespace/control chars"
    p = urlsplit(url)
    if p.scheme not in ("http", "https"): return "scheme must be http or https"
    if not p.hostname: return "missing host"
    if p.username or p.password: return "credentials in url not allowed"
    host = p.hostname.lower().rstrip(".")
    if host in BLOCKED_HOSTS or host.endswith(".localhost") or host.endswith(".internal"): return "internal host blocked"
    if self_host and host == self_host: return "redirect loop to shortener"
    addrs = []
    try:
        addrs = [ipaddress.ip_address(host)]
    except ValueError:
        if resolve:
            try: addrs = [ipaddress.ip_address(a[4][0]) for a in socket.getaddrinfo(host, None)]
            except OSError: return "unresolvable host"
    for ip in addrs:
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return "private/internal address blocked"
    return None


class RateLimiter:
    """Token bucket per key. capacity tokens, refilled at rate/sec. Thread-safe, in-memory (single instance)."""
    def __init__(self, capacity: int, rate: float):
        self.cap, self.rate, self.b, self.lock = capacity, rate, {}, threading.Lock()

    def allow(self, key: str) -> tuple[bool, float]:
        now = time.monotonic()
        with self.lock:
            tokens, last = self.b.get(key, (self.cap, now))
            tokens = min(self.cap, tokens + (now - last) * self.rate)
            if tokens >= 1:
                self.b[key] = (tokens - 1, now); return True, 0.0
            self.b[key] = (tokens, now); return False, (1 - tokens) / self.rate
