"""Security primitives: password hashing, flag hashing, tokens, rate limiting."""
import collections
import hashlib
import hmac
import os
import re
import secrets
import threading
import time

# Module-level so tests (or operators) can tune the cost; stored hashes carry their own parameters.
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 128 * 1024 * 1024

USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,24}$")
MIN_PASSWORD, MAX_PASSWORD = 8, 128
MAX_FLAG_LENGTH = 256


def valid_username(name):
    return bool(USERNAME_RE.match(name or ""))


def valid_password(pw):
    return isinstance(pw, str) and MIN_PASSWORD <= len(pw) <= MAX_PASSWORD


def _scrypt(password, salt, n, r, p):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          dklen=32, maxmem=SCRYPT_MAXMEM)


def hash_password(password):
    """Return 'scrypt$N$r$p$salt_hex$hash_hex'."""
    salt = os.urandom(16)
    dk = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    return "scrypt$%d$%d$%d$%s$%s" % (SCRYPT_N, SCRYPT_R, SCRYPT_P, salt.hex(), dk.hex())


def verify_password(password, stored):
    """Constant-time check. Malformed stored values simply fail."""
    try:
        scheme, n, r, p, salt_hex, hash_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = bytes.fromhex(hash_hex)
        actual = _scrypt(password, bytes.fromhex(salt_hex), int(n), int(r), int(p))
    except (ValueError, AttributeError, TypeError, MemoryError):
        return False
    return hmac.compare_digest(actual, expected)


_dummy_hash = None


def dummy_verify(password):
    """Spend the same time as a real check, used when the user does not exist."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password("not-a-real-password")
    verify_password(password, _dummy_hash)
    return False


def normalize_flag(flag):
    return flag.strip()


def hash_flag(flag):
    """SHA-256 hex digest of a flag. Flags must be long and random for this to be safe."""
    return hashlib.sha256(normalize_flag(flag).encode("utf-8")).hexdigest()


def check_flag(submitted, stored_hex):
    return hmac.compare_digest(hash_flag(submitted), stored_hex)


def new_token():
    return secrets.token_urlsafe(32)


class RateLimiter:
    """Sliding-window limiter: at most `limit` events per `window` seconds per key."""

    def __init__(self, limit, window, clock=time.monotonic):
        self.limit, self.window, self.clock = limit, window, clock
        self._events = collections.defaultdict(collections.deque)
        self._lock = threading.Lock()

    def _prune(self, q, now):
        while q and now - q[0] >= self.window:
            q.popleft()

    def allow(self, key):
        """Record an event; return False when the key is over its limit."""
        with self._lock:
            now = self.clock()
            q = self._events[key]
            self._prune(q, now)
            if len(q) >= self.limit:
                return False
            q.append(now)
            if len(self._events) > 10000:  # bound memory under key-spraying
                for k in [k for k, v in self._events.items() if not v or now - v[-1] >= self.window]:
                    del self._events[k]
            return True

    def retry_after(self, key):
        with self._lock:
            q = self._events.get(key)
            if not q:
                return 0
            return max(0, int(self.window - (self.clock() - q[0])) + 1)
