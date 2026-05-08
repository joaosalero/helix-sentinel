"""Repository protocols for identity lookups."""

from typing import Protocol
from uuid import UUID

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.auth.rbac import permissions_for_roles
from app.users.models import Permission, Role, RolePermission, User, UserRole, UserStatus
from app.users.schemas import StoredUser


class UserRepository(Protocol):
    """Identity lookup boundary used by authentication services."""

    async def get_by_email(self, email: str) -> StoredUser | None:
        """Return a user by normalized email."""

    async def get_by_id(self, user_id: UUID) -> StoredUser | None:
        """Return a user by stable UUID."""


class InMemoryUserRepository:
    """Small test/local repository that mirrors the production lookup contract."""

    def __init__(self, users: list[StoredUser] | None = None) -> None:
        self._users_by_email = {user.email.lower(): user for user in users or []}
        self._users_by_id = {user.id: user for user in users or []}

    async def get_by_email(self, email: str) -> StoredUser | None:
        return self._users_by_email.get(email.lower())

    async def get_by_id(self, user_id: UUID) -> StoredUser | None:
        return self._users_by_id.get(user_id)


class PostgresUserRepository:
    """PostgreSQL-backed identity lookup adapter for authentication flows."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def get_by_email(self, email: str) -> StoredUser | None:
        normalized_email = email.lower()
        statement = select(User).where(func.lower(User.email) == normalized_email)
        return await self._get_user(statement)

    async def get_by_id(self, user_id: UUID) -> StoredUser | None:
        statement = select(User).where(User.id == user_id)
        return await self._get_user(statement)

    async def _get_user(self, statement: Select[tuple[User]]) -> StoredUser | None:
        async with self.session_factory() as session:
            user = await session.scalar(statement)
            if user is None:
                return None
            roles = await _role_names(session, user.id)
            permissions = await _permission_names(session, user.id)
            return _to_stored_user(user, roles, permissions)


async def _role_names(session: AsyncSession, user_id: UUID) -> frozenset[str]:
    result = await session.scalars(
        select(Role.name)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
    )
    return frozenset(result.all())


async def _permission_names(session: AsyncSession, user_id: UUID) -> frozenset[str]:
    result = await session.execute(
        select(Permission.resource, Permission.action)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(UserRole, UserRole.role_id == RolePermission.role_id)
        .where(UserRole.user_id == user_id)
    )
    return frozenset(f"{resource}:{action}" for resource, action in result.all())


def _to_stored_user(
    user: User,
    roles: frozenset[str],
    permissions: frozenset[str],
) -> StoredUser:
    try:
        status = UserStatus(user.status)
    except ValueError:
        status = UserStatus.DISABLED
    return StoredUser(
        id=user.id,
        tenant_id="default",
        email=user.email,
        display_name=user.display_name,
        password_hash=user.password_hash,
        status=status,
        roles=roles,
        permissions=permissions | permissions_for_roles(roles),
        is_superuser=user.is_superuser,
    )
