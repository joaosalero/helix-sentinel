"""Authentication and authorization dependencies for protected routes."""

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.audit.events import AuditAction
from app.audit.repositories import AuditRepository, InMemoryAuditRepository
from app.audit.service import AuditService
from app.auth.service import AuthenticationService, claims_subject_as_uuid
from app.core.config.settings import SecuritySettings, get_security_settings
from app.core.exceptions.security import AuthenticationError, AuthorizationError
from app.core.security.tokens import TokenService, TokenType
from app.users.models import UserStatus
from app.users.repositories import InMemoryUserRepository, UserRepository
from app.users.schemas import Principal

bearer_scheme = HTTPBearer(auto_error=False)

_default_user_repository = InMemoryUserRepository()
_default_audit_repository = InMemoryAuditRepository()


def get_user_repository() -> UserRepository:
    """Return the identity repository.

    Production wiring should replace this in-memory implementation with a
    database-backed repository while preserving the protocol.
    """
    return _default_user_repository


def get_audit_service() -> AuditService:
    """Return the audit service used by security dependencies."""
    return AuditService(_default_audit_repository)


def get_token_service(
    settings: Annotated[SecuritySettings, Depends(get_security_settings)],
) -> TokenService:
    """Return the JWT token service."""
    return TokenService(settings)


def get_authentication_service(
    users: Annotated[UserRepository, Depends(get_user_repository)],
    tokens: Annotated[TokenService, Depends(get_token_service)],
    audit: Annotated[AuditService, Depends(get_audit_service)],
    settings: Annotated[SecuritySettings, Depends(get_security_settings)],
) -> AuthenticationService:
    """Return the authentication application service."""
    return AuthenticationService(users=users, tokens=tokens, audit=audit, settings=settings)


async def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    users: Annotated[UserRepository, Depends(get_user_repository)],
    tokens: Annotated[TokenService, Depends(get_token_service)],
    audit: Annotated[AuditService, Depends(get_audit_service)],
) -> Principal:
    """Authenticate a bearer access token and return the current principal."""
    if credentials is None:
        raise AuthenticationError

    claims = tokens.validate(credentials.credentials, TokenType.ACCESS)
    user = await users.get_by_id(claims_subject_as_uuid(claims.subject))
    if user is None or user.status != UserStatus.ACTIVE:
        await audit.record(
            AuditAction.USER_STATE_REJECTED,
            "failure",
            correlation_id=getattr(request.state, "correlation_id", None),
        )
        raise AuthenticationError

    return user.to_principal()


async def resolve_current_user_from_request(request: Request) -> Principal:
    """Resolve the current principal without FastAPI dependency injection.

    This supports explicit route wiring and keeps authentication behavior
    testable in environments where dependency execution is constrained.
    """
    authorization = request.headers.get("Authorization")
    if authorization is None or not authorization.startswith("Bearer "):
        raise AuthenticationError

    users = get_state_user_repository(request)
    tokens = TokenService(get_state_security_settings(request))
    audit = AuditService(get_state_audit_repository(request))
    claims = tokens.validate(authorization.removeprefix("Bearer ").strip(), TokenType.ACCESS)
    user = await users.get_by_id(claims_subject_as_uuid(claims.subject))
    if user is None or user.status != UserStatus.ACTIVE:
        await audit.record(
            AuditAction.USER_STATE_REJECTED,
            "failure",
            correlation_id=getattr(request.state, "correlation_id", None),
        )
        raise AuthenticationError
    return user.to_principal()


def get_state_user_repository(request: Request) -> UserRepository:
    """Return the request app's user repository or the local default."""
    return getattr(request.app.state, "user_repository", _default_user_repository)


def get_state_audit_repository(request: Request) -> AuditRepository:
    """Return the request app's audit repository or the local default."""
    return getattr(request.app.state, "audit_repository", _default_audit_repository)


def get_state_security_settings(request: Request) -> SecuritySettings:
    """Return request app security settings or environment settings."""
    return getattr(request.app.state, "security_settings", get_security_settings())


def build_authentication_service_from_request(request: Request) -> AuthenticationService:
    """Build the authentication service from explicit app-state dependencies."""
    settings = get_state_security_settings(request)
    return AuthenticationService(
        users=get_state_user_repository(request),
        tokens=TokenService(settings),
        audit=AuditService(get_state_audit_repository(request)),
        settings=settings,
    )


async def ensure_roles_for_request(
    request: Request,
    principal: Principal,
    required_roles: set[str],
) -> None:
    """Enforce role authorization and audit denials."""
    if principal.is_superuser or principal.roles.intersection(required_roles):
        return
    await AuditService(get_state_audit_repository(request)).record(
        AuditAction.PERMISSION_DENIED,
        "failure",
        actor_id=principal.id,
        actor_email=principal.email,
        correlation_id=getattr(request.state, "correlation_id", None),
        metadata={"required_roles": sorted(required_roles)},
    )
    raise AuthorizationError


async def ensure_permissions_for_request(
    request: Request,
    principal: Principal,
    required_permissions: set[str],
) -> None:
    """Enforce permission authorization and audit denials."""
    if principal.is_superuser or required_permissions.issubset(principal.permissions):
        return
    await AuditService(get_state_audit_repository(request)).record(
        AuditAction.PERMISSION_DENIED,
        "failure",
        actor_id=principal.id,
        actor_email=principal.email,
        correlation_id=getattr(request.state, "correlation_id", None),
        metadata={"required_permissions": sorted(required_permissions)},
    )
    raise AuthorizationError


def require_roles(*required_roles: str) -> Callable[..., Awaitable[Principal]]:
    """Build a dependency that requires at least one role."""

    async def guard(
        request: Request,
        principal: Annotated[Principal, Depends(get_current_user)],
        audit: Annotated[AuditService, Depends(get_audit_service)],
    ) -> Principal:
        if principal.is_superuser or principal.roles.intersection(required_roles):
            return principal
        await audit.record(
            AuditAction.PERMISSION_DENIED,
            "failure",
            actor_id=principal.id,
            actor_email=principal.email,
            correlation_id=getattr(request.state, "correlation_id", None),
            metadata={"required_roles": list(required_roles)},
        )
        raise AuthorizationError

    return guard


def require_permissions(*required_permissions: str) -> Callable[..., Awaitable[Principal]]:
    """Build a dependency that requires all requested permissions."""

    async def guard(
        request: Request,
        principal: Annotated[Principal, Depends(get_current_user)],
        audit: Annotated[AuditService, Depends(get_audit_service)],
    ) -> Principal:
        if principal.is_superuser or set(required_permissions).issubset(principal.permissions):
            return principal
        await audit.record(
            AuditAction.PERMISSION_DENIED,
            "failure",
            actor_id=principal.id,
            actor_email=principal.email,
            correlation_id=getattr(request.state, "correlation_id", None),
            metadata={"required_permissions": list(required_permissions)},
        )
        raise AuthorizationError

    return guard
