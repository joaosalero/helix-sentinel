"""Identity and RBAC persistence models."""

from uuid import UUID

from sqlalchemy import Boolean, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from helix_sentinel.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Platform user account.

    Password hashes are write-only from an API perspective and must never be
    emitted in logs, events, or response schemas.
    """

    __tablename__ = "identity_users"

    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(160), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    role_assignments: Mapped[list["RoleAssignment"]] = relationship(
        "helix_sentinel.domains.identity.models.RoleAssignment",
        back_populates="user",
    )


class Role(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """RBAC role used to group least-privilege permissions."""

    __tablename__ = "identity_roles"

    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(String(500))

    permissions: Mapped[list["Permission"]] = relationship(
        "helix_sentinel.domains.identity.models.Permission",
        back_populates="role",
    )


class Permission(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Fine-grained permission attached to a role."""

    __tablename__ = "identity_permissions"
    __table_args__ = (UniqueConstraint("role_id", "resource", "action"),)

    role_id: Mapped[UUID] = mapped_column(ForeignKey("identity_roles.id"), nullable=False)
    resource: Mapped[str] = mapped_column(String(120), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False)

    role: Mapped[Role] = relationship(
        "helix_sentinel.domains.identity.models.Role",
        back_populates="permissions",
    )


class RoleAssignment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """User-to-role assignment with explicit auditability."""

    __tablename__ = "identity_role_assignments"
    __table_args__ = (
        UniqueConstraint("user_id", "role_id"),
        Index("ix_identity_role_assignments_user_role", "user_id", "role_id"),
    )

    user_id: Mapped[UUID] = mapped_column(ForeignKey("identity_users.id"), nullable=False)
    role_id: Mapped[UUID] = mapped_column(ForeignKey("identity_roles.id"), nullable=False)

    user: Mapped[User] = relationship(
        "helix_sentinel.domains.identity.models.User",
        back_populates="role_assignments",
    )
    role: Mapped[Role] = relationship("helix_sentinel.domains.identity.models.Role")
