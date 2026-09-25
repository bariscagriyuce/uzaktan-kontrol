import base64
import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

_SCRYPT = dict(n=2**15, r=8, p=1, maxmem=64 * 1024 * 1024)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, dklen=32, **_SCRYPT)
    return "scrypt$%s$%s" % (
        base64.b64encode(salt).decode(),
        base64.b64encode(dk).decode(),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt_b64, dk_b64 = stored.split("$")
    except ValueError:
        return False
    if algo != "scrypt":
        return False
    dk = hashlib.scrypt(
        password.encode(), salt=base64.b64decode(salt_b64), dklen=32, **_SCRYPT
    )
    return hmac.compare_digest(dk, base64.b64decode(dk_b64))


# Checked against when the username does not exist, so both paths cost the same.
DUMMY_HASH = hash_password(secrets.token_hex(16))


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def account_auth_msg(rd_id: str, uuid: str, pw_hash: str, timestamp: str) -> bytes:
    # Must match `account_auth_signed_msg` in the client's src/hbbs_http/sync.rs.
    return f"account-auth\0{rd_id}\0{uuid}\0{pw_hash}\0{timestamp}".encode()


def verify_device_signature(pk_b64: str, msg: bytes, sig_b64: str) -> bool:
    try:
        VerifyKey(base64.b64decode(pk_b64)).verify(msg, base64.b64decode(sig_b64))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


class RateLimiter:
    """Counts failures per key inside a sliding window."""

    def __init__(self, max_failures: int, window_secs: int):
        self.max = max_failures
        self.window = window_secs
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _trim(self, q: deque, t: float) -> None:
        while q and q[0] <= t - self.window:
            q.popleft()

    def blocked(self, key: str) -> bool:
        t = time.monotonic()
        with self._lock:
            q = self._hits[key]
            self._trim(q, t)
            return len(q) >= self.max

    def fail(self, key: str) -> None:
        t = time.monotonic()
        with self._lock:
            q = self._hits[key]
            self._trim(q, t)
            q.append(t)

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)
