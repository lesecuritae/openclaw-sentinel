"""One authentication boundary for HTTP, MCP and WebSocket access."""

import hashlib
import secrets
from dataclasses import dataclass

from fastapi import HTTPException, Request

from core.permissions import ROLE_SCOPES, Role


@dataclass(frozen=True)
class Principal:
    user_id: str
    role: Role
    session_id: str

    def require(self, scope: str) -> None:
        if scope not in ROLE_SCOPES[self.role]:
            raise HTTPException(403, "insufficient scope")


def credential_principal(state, token: str) -> Principal | None:
    if not token or len(token) > 4096:
        return None
    digest = hashlib.sha256(token.encode()).hexdigest()
    user = state.store.user_by_credential(digest)
    if user:
        if not user["enabled"]:
            return None
        try:
            return Principal(str(user["id"]), Role(user["role"]), digest[:24])
        except ValueError:
            return None
    matches = [
        Role(role)
        for role, key in state.settings.role_credentials.items()
        if key and secrets.compare_digest(token.encode(), key.encode())
    ]
    if len(matches) != 1:
        return None
    return Principal(f"configured:{matches[0].value}", matches[0], digest[:24])


def resolve_principal(state, token: str) -> Principal | None:
    if state.web_sessions.enabled:
        digest = state.web_sessions.credential(token)
        if not digest:
            return None
        # Re-resolve on every request: role changes, rotation and disabling take effect now.
        user = state.store.user_by_credential(digest)
        if user:
            if not user["enabled"] or user["role"] not in Role:
                return None
            return Principal(
                str(user["id"]), Role(user["role"]), state.web_sessions._hash(token)[:24]
            )
        for role, key in state.settings.role_credentials.items():
            if key and hashlib.sha256(key.encode()).hexdigest() == digest:
                return Principal(
                    f"configured:{role}", Role(role), state.web_sessions._hash(token)[:24]
                )
        return None
    return credential_principal(state, token)


def authenticate(request: Request) -> None:
    header = request.headers.get("authorization", "")
    token = header[7:] if header.startswith("Bearer ") else ""
    principal = resolve_principal(request.app.state, token)
    if principal is None:
        raise HTTPException(401, "invalid or expired credentials")
    request.state.principal = principal
    request.state.role = principal.role
    request.state.scopes = ROLE_SCOPES[principal.role]


def scoped(scope: str):
    def dependency(request: Request):
        authenticate(request)
        request.state.principal.require(scope)

    return dependency


def audit(request: Request, action: str, before=None, after=None):
    principal = request.state.principal
    request.app.state.store.add_audit(
        principal.user_id, action, before, after, session_id=principal.session_id
    )
