"""RBAC role and permission definitions for Helix Sentinel."""

from enum import StrEnum


class SystemRole(StrEnum):
    """Built-in roles for the initial SaaS security model."""

    ADMIN = "admin"
    ANALYST = "analyst"
    ENGINEER = "engineer"
    VIEWER = "viewer"


class Permission(StrEnum):
    """Permission constants used by route guards."""

    USERS_READ = "users:read"
    USERS_WRITE = "users:write"
    DETECTIONS_READ = "detections:read"
    DETECTIONS_WRITE = "detections:write"
    ANALYTICS_READ = "analytics:read"
    AUDIT_READ = "audit:read"


ROLE_PERMISSIONS: dict[SystemRole, frozenset[Permission]] = {
    SystemRole.ADMIN: frozenset(Permission),
    SystemRole.ENGINEER: frozenset(
        {
            Permission.USERS_READ,
            Permission.DETECTIONS_READ,
            Permission.DETECTIONS_WRITE,
            Permission.ANALYTICS_READ,
            Permission.AUDIT_READ,
        }
    ),
    SystemRole.ANALYST: frozenset(
        {
            Permission.DETECTIONS_READ,
            Permission.ANALYTICS_READ,
            Permission.AUDIT_READ,
        }
    ),
    SystemRole.VIEWER: frozenset({Permission.DETECTIONS_READ, Permission.ANALYTICS_READ}),
}


def permissions_for_roles(roles: set[str] | frozenset[str]) -> frozenset[str]:
    """Resolve effective permission names for built-in roles."""
    resolved: set[str] = set()
    for role in roles:
        try:
            resolved.update(permission.value for permission in ROLE_PERMISSIONS[SystemRole(role)])
        except ValueError:
            continue
    return frozenset(resolved)

