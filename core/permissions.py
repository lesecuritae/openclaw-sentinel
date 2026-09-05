from enum import StrEnum

from fastapi import HTTPException, Request


class Role(StrEnum):
    ADMINISTRATOR = "administrator"
    ANALYST = "analyst"
    VIEWER = "viewer"


_levels = {Role.VIEWER: 0, Role.ANALYST: 1, Role.ADMINISTRATOR: 2}


def current_role(request: Request) -> Role:
    value = request.headers.get("x-sentinel-role", Role.ADMINISTRATOR.value).lower()
    try:
        return Role(value)
    except ValueError:
        raise HTTPException(status_code=403, detail="invalid role") from None


def require_role(request: Request, minimum: Role) -> None:
    if _levels[current_role(request)] < _levels[minimum]:
        raise HTTPException(status_code=403, detail="insufficient role")
