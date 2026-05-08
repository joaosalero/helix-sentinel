"""User repository adapter tests."""

from uuid import uuid4

from app.auth.rbac import Permission, SystemRole
from app.users.models import User, UserStatus
from app.users.repositories import PostgresUserRepository, _to_stored_user
from helix_sentinel.core.config import Settings
from helix_sentinel.main import create_app


def test_authoritative_runtime_uses_postgres_user_repository() -> None:
    app = create_app(
        Settings(
            environment="test",
            secret_key="test-secret-key-with-at-least-32-bytes",
            database_url="postgresql+asyncpg://helix:helix@localhost:5432/helix_sentinel_test",
        )
    )

    assert isinstance(app.state.user_repository, PostgresUserRepository)


def test_postgres_user_repository_maps_stored_user_with_role_permissions() -> None:
    user = User(
        id=uuid4(),
        email="analyst@example.com",
        display_name="SOC Analyst",
        password_hash="argon2-hash",
        status=UserStatus.ACTIVE.value,
        is_superuser=False,
    )

    stored = _to_stored_user(
        user,
        frozenset({SystemRole.ANALYST.value}),
        frozenset({Permission.USERS_READ.value}),
    )

    assert stored.email == "analyst@example.com"
    assert stored.status == UserStatus.ACTIVE
    assert stored.password_hash == "argon2-hash"
    assert stored.roles == frozenset({SystemRole.ANALYST.value})
    assert Permission.USERS_READ.value in stored.permissions
    assert Permission.ANALYTICS_READ.value in stored.permissions


def test_postgres_user_repository_treats_unknown_status_as_disabled() -> None:
    user = User(
        id=uuid4(),
        email="bad-state@example.com",
        display_name="Bad State",
        password_hash="argon2-hash",
        status="unexpected",
        is_superuser=False,
    )

    stored = _to_stored_user(user, frozenset(), frozenset())

    assert stored.status == UserStatus.DISABLED
