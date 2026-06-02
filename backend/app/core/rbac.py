"""Role-based access control."""
from functools import wraps
from typing import Callable, List

from fastapi import Depends, HTTPException, status

from backend.app.api.deps import get_current_user
from backend.app.models.documents import User
from backend.app.models.enums import UserRole

ROLE_PERMISSIONS = {
    UserRole.SUPER_ADMIN: ["*"],
    UserRole.SOC_MANAGER: [
        "alerts:read", "alerts:write", "incidents:read", "incidents:write",
        "users:read", "users:invite", "reports:read", "reports:write",
        "discovery:approve", "ips:approve", "dashboard:all",
    ],
    UserRole.SECURITY_ANALYST: [
        "alerts:read", "alerts:write", "incidents:read", "incidents:write",
        "events:read", "hunting:read", "hunting:write", "dashboard:all",
    ],
    UserRole.THREAT_HUNTER: [
        "alerts:read", "events:read", "hunting:read", "hunting:write",
        "intel:read", "dashboard:all",
    ],
    UserRole.INCIDENT_RESPONDER: [
        "alerts:read", "alerts:write", "incidents:read", "incidents:write",
        "ips:approve", "dashboard:all",
    ],
    UserRole.AUDITOR: [
        "alerts:read", "incidents:read", "audit:read", "reports:read", "dashboard:read",
    ],
    UserRole.READ_ONLY: [
        "alerts:read", "events:read", "dashboard:read",
    ],
}


def has_permission(user: User, permission: str) -> bool:
    perms = ROLE_PERMISSIONS.get(user.role, [])
    return "*" in perms or permission in perms


def require_roles(allowed_roles: List[UserRole]):
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, current_user: User = Depends(get_current_user), **kwargs):
            if current_user.role not in allowed_roles and current_user.role != UserRole.SUPER_ADMIN:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator


def require_permission(permission: str):
    async def checker(current_user: User = Depends(get_current_user)) -> User:
        if not has_permission(current_user, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission}",
            )
        return current_user
    return checker
