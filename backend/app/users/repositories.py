"""Repository protocols for identity lookups."""

from typing import Protocol
from uuid import UUID

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

