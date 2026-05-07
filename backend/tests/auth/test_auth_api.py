"""Authentication endpoint and RBAC integration tests."""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.app import create_security_app
from app.audit.repositories import InMemoryAuditRepository
from app.auth.rbac import permissions_for_roles
from app.core.config.settings import SecuritySettings
from app.core.security.passwords import hash_password
from app.users.models import UserStatus
from app.users.repositories import InMemoryUserRepository
from app.users.schemas import StoredUser


@dataclass
class SecurityTestContext:
    """Test wiring for auth API dependencies."""

    client: AsyncClient
    audit_repository: InMemoryAuditRepository
    analyst: StoredUser
    admin: StoredUser


@pytest.fixture
async def security_context() -> AsyncIterator[SecurityTestContext]:
    analyst_roles = frozenset({"analyst"})
    admin_roles = frozenset({"admin"})
    analyst = StoredUser(
        id=uuid4(),
        email="analyst@example.com",
        display_name="SOC Analyst",
        password_hash=hash_password("valid analyst password"),
        status=UserStatus.ACTIVE,
        roles=analyst_roles,
        permissions=permissions_for_roles(analyst_roles),
    )
    admin = StoredUser(
        id=uuid4(),
        email="admin@example.com",
        display_name="Security Admin",
        password_hash=hash_password("valid admin password"),
        status=UserStatus.ACTIVE,
        roles=admin_roles,
        permissions=permissions_for_roles(admin_roles),
    )
    users = InMemoryUserRepository([analyst, admin])
    audit_repository = InMemoryAuditRepository()
    settings = SecuritySettings(
        environment="test",
        auth_secret_key="test-access-secret-with-at-least-32-bytes",
        auth_refresh_secret_key="test-refresh-secret-with-at-least-32-bytes",
    )

    app = create_security_app()
    app.state.user_repository = users
    app.state.audit_repository = audit_repository
    app.state.security_settings = settings

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield SecurityTestContext(
            client=client,
            audit_repository=audit_repository,
            analyst=analyst,
            admin=admin,
        )


async def test_login_returns_token_pair_and_audit_event(
    security_context: SecurityTestContext,
) -> None:
    response = await security_context.client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@example.com", "password": "valid analyst password"},
        headers={"X-Correlation-ID": "corr-login"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["refresh_token"]
    assert security_context.audit_repository.events[-1].action == "auth.login_succeeded"
    assert security_context.audit_repository.events[-1].correlation_id == "corr-login"


async def test_invalid_login_uses_generic_failure_and_audit(
    security_context: SecurityTestContext,
) -> None:
    response = await security_context.client.post(
        "/api/v1/auth/login",
        json={"email": "missing@example.com", "password": "wrong password"},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}
    event = security_context.audit_repository.events[-1]
    assert event.action == "auth.login_failed"
    assert event.actor_email_hash is not None
    assert "password" not in event.metadata


async def test_refresh_issues_new_token_pair(security_context: SecurityTestContext) -> None:
    login_response = await security_context.client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@example.com", "password": "valid analyst password"},
    )
    refresh_token = login_response.json()["refresh_token"]

    response = await security_context.client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )

    assert response.status_code == 200
    assert response.json()["access_token"]
    assert security_context.audit_repository.events[-1].action == "auth.token_refreshed"


async def test_protected_route_requires_access_token(security_context: SecurityTestContext) -> None:
    response = await security_context.client.get("/api/v1/security/me")

    assert response.status_code == 401


async def test_permission_guard_allows_analyst(security_context: SecurityTestContext) -> None:
    login_response = await security_context.client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@example.com", "password": "valid analyst password"},
    )
    access_token = login_response.json()["access_token"]

    response = await security_context.client.get(
        "/api/v1/security/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200
    assert response.json()["email"] == "analyst@example.com"


async def test_role_guard_denies_non_admin_and_audits(
    security_context: SecurityTestContext,
) -> None:
    login_response = await security_context.client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@example.com", "password": "valid analyst password"},
    )
    access_token = login_response.json()["access_token"]

    response = await security_context.client.get(
        "/api/v1/security/admin",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 403
    assert security_context.audit_repository.events[-1].action == "auth.permission_denied"


async def test_security_middleware_sets_correlation_and_headers(
    security_context: SecurityTestContext,
) -> None:
    response = await security_context.client.get(
        "/api/v1/security/me",
        headers={"X-Correlation-ID": "corr-middleware"},
    )

    assert response.headers["X-Correlation-ID"] == "corr-middleware"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
