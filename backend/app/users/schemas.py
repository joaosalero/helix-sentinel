"""User and principal schemas used by authentication dependencies."""

from uuid import UUID

from pydantic import BaseModel, Field

from app.users.models import UserStatus


class Principal(BaseModel):
    """Authenticated user context trusted by route guards."""

    id: UUID
    tenant_id: str = Field(default="default", min_length=1, max_length=80)
    email: str = Field(min_length=3, max_length=320)
    display_name: str
    status: UserStatus
    roles: frozenset[str]
    permissions: frozenset[str]
    is_superuser: bool = False


class StoredUser(BaseModel):
    """Internal identity record including password hash."""

    id: UUID
    tenant_id: str = Field(default="default", min_length=1, max_length=80)
    email: str = Field(min_length=3, max_length=320)
    display_name: str
    password_hash: str
    status: UserStatus
    roles: frozenset[str]
    permissions: frozenset[str]
    is_superuser: bool = False

    def to_principal(self) -> Principal:
        """Return a password-free authenticated principal."""
        return Principal(
            id=self.id,
            tenant_id=self.tenant_id,
            email=self.email,
            display_name=self.display_name,
            status=self.status,
            roles=self.roles,
            permissions=self.permissions,
            is_superuser=self.is_superuser,
        )
