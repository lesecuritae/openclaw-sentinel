import base64
import hashlib
import hmac
import secrets
import struct
import time
from collections import defaultdict, deque
from pathlib import Path


def totp(secret: str, timestamp: float | None = None) -> str:
    normalized = secret.strip().replace(" ", "").upper()
    key = base64.b32decode(normalized, casefold=True)
    counter = int((timestamp if timestamp is not None else time.time()) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{value:06d}"


class WebSessionManager:
    def __init__(
        self,
        *,
        enabled: bool,
        api_key: str,
        secret: str = "",
        secret_file: Path | None = None,
        ttl_seconds: int = 900,
        max_attempts: int = 5,
    ):
        self.enabled = enabled
        self.api_key = api_key
        self.ttl_seconds = ttl_seconds
        self.max_attempts = max_attempts
        self.sessions: dict[str, float] = {}
        self.session_credentials: dict[str, str] = {}
        self.attempts: dict[str, deque[float]] = defaultdict(deque)
        file_secret = secret_file.read_text().strip() if secret_file else ""
        self.secret = secret.strip() or file_secret
        if enabled and not self.secret:
            raise ValueError("Web 2FA requires a TOTP secret")
        if self.secret:
            try:
                base64.b32decode(self.secret.replace(" ", "").upper(), casefold=True)
            except Exception as exc:
                raise ValueError("Invalid base32 Web 2FA secret") from exc

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def login(
        self,
        client: str,
        api_key: str,
        code: str,
        now: float | None = None,
        *,
        credential_verified: bool = False,
    ) -> str | None:
        current = now if now is not None else time.time()
        self.sessions = {
            key: expires for key, expires in self.sessions.items() if expires > current
        }
        self.session_credentials = {
            k: v for k, v in self.session_credentials.items() if k in self.sessions
        }
        if client not in self.attempts and len(self.attempts) >= 10000:
            return None
        attempts = self.attempts[client]
        while attempts and attempts[0] <= current - 300:
            attempts.popleft()
        if len(attempts) >= self.max_attempts:
            return None
        valid_key = credential_verified or bool(
            self.api_key and secrets.compare_digest(api_key, self.api_key)
        )
        valid_code = len(code) == 6 and any(
            secrets.compare_digest(code, totp(self.secret, current + drift))
            for drift in (-30, 0, 30)
        )
        if not (valid_key and valid_code):
            attempts.append(current)
            return None
        attempts.clear()
        if len(self.sessions) >= 10_000:
            return None
        token = secrets.token_urlsafe(32)
        self.sessions[self._hash(token)] = current + self.ttl_seconds
        self.session_credentials[self._hash(token)] = self._hash(api_key)
        return token

    def validate(self, token: str, now: float | None = None) -> bool:
        current = now if now is not None else time.time()
        key = self._hash(token)
        expires = self.sessions.get(key, 0)
        if expires <= current:
            self.sessions.pop(key, None)
            return False
        return True

    def credential(self, token: str) -> str | None:
        return self.session_credentials.get(self._hash(token)) if self.validate(token) else None

    def logout(self, token: str) -> None:
        self.sessions.pop(self._hash(token), None)
        self.session_credentials.pop(self._hash(token), None)
