"""Minimal protected routes used to validate authorization wiring."""

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.auth.rbac import Permission, SystemRole
from app.core.dependencies.security import (
    ensure_permissions_for_request,
    ensure_roles_for_request,
    resolve_current_user_from_request,
)

router = APIRouter(prefix="/security", tags=["security"])


class PrincipalResponse(BaseModel):
    """Password-free principal response for protected route checks."""

    email: str
    roles: list[str]
    permissions: list[str]


@router.get("/me", response_model=PrincipalResponse)
async def me(
    request: Request,
) -> PrincipalResponse:
    """Return current principal metadata for authenticated users."""
    principal = await resolve_current_user_from_request(request)
    await ensure_permissions_for_request(request, principal, {Permission.ANALYTICS_READ.value})
    return PrincipalResponse(
        email=principal.email,
        roles=sorted(principal.roles),
        permissions=sorted(principal.permissions),
    )


@router.get("/admin", response_model=PrincipalResponse)
async def admin_only(
    request: Request,
) -> PrincipalResponse:
    """Validate role-based route protection."""
    principal = await resolve_current_user_from_request(request)
    await ensure_roles_for_request(request, principal, {SystemRole.ADMIN.value})
    return PrincipalResponse(
        email=principal.email,
        roles=sorted(principal.roles),
        permissions=sorted(principal.permissions),
    )
