from enum import StrEnum

from fastapi import HTTPException, Request


class Role(StrEnum):
    ADMINISTRATOR = "administrator"
    ANALYST = "analyst"
    VIEWER = "viewer"


ROLE_SCOPES = {
    Role.VIEWER: frozenset({"incident.read", "policy.read", "action.read"}),
    Role.ANALYST: frozenset(
        {"incident.read", "policy.read", "action.read", "report.create", "llm.analyze"}
    ),
    Role.ADMINISTRATOR: frozenset(
        {
            "incident.read",
            "incident.write",
            "policy.read",
            "policy.write",
            "action.read",
            "action.execute",
            "config.export",
            "config.write",
            "user.read",
            "audit.read",
            "report.create",
            "llm.analyze",
        }
    ),
}

_levels = {Role.VIEWER: 0, Role.ANALYST: 1, Role.ADMINISTRATOR: 2}


def current_role(request: Request) -> Role:
    value = getattr(request.state, "role", None)
    if value is None:
        raise HTTPException(status_code=401, detail="authenticated role required")
    if isinstance(value, Role):
        return value
    try:
        return Role(str(value).lower())
    except ValueError:
        raise HTTPException(status_code=403, detail="invalid role") from None


def require_role(request: Request, minimum: Role) -> None:
    if _levels[current_role(request)] < _levels[minimum]:
        raise HTTPException(status_code=403, detail="insufficient role")


def require_scope(request: Request, scope: str) -> None:
    scopes = getattr(request.state, "scopes", set())
    if scope not in scopes:
        raise HTTPException(status_code=403, detail="insufficient scope")
