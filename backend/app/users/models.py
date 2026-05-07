"""User and RBAC persistence models."""

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for identity and audit migrations."""


class UserStatus(StrEnum):
    """Account states used by authentication decisions."""

    ACTIVE = "active"
    DISABLED = "disabled"
    LOCKED = "locked"
    PENDING = "pending"


class User(Base):
    """Secure user account model.

    Password hashes are never exposed through API schemas or audit metadata.
    """

    __tablename__ = "auth_users"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(160), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default=UserStatus.ACTIVE.value)
    is_superuser: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    roles: Mapped[list["UserRole"]] = relationship(back_populates="user")


class Role(Base):
    """RBAC role grouping operational permissions."""

    __tablename__ = "auth_roles"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(String(500))
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    permissions: Mapped[list["RolePermission"]] = relationship(back_populates="role")


class Permission(Base):
    """Fine-grained permission used by route guards."""

    __tablename__ = "auth_permissions"
    __table_args__ = (UniqueConstraint("resource", "action"),)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    resource: Mapped[str] = mapped_column(String(120), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500))


class UserRole(Base):
    """User-to-role assignment with uniqueness constraints."""

    __tablename__ = "auth_user_roles"
    __table_args__ = (
        UniqueConstraint("user_id", "role_id"),
        Index("ix_auth_user_roles_user_role", "user_id", "role_id"),
    )

    user_id: Mapped[UUID] = mapped_column(ForeignKey("auth_users.id"), primary_key=True)
    role_id: Mapped[UUID] = mapped_column(ForeignKey("auth_roles.id"), primary_key=True)

    user: Mapped[User] = relationship(back_populates="roles")
    role: Mapped[Role] = relationship()


class RolePermission(Base):
    """Role-to-permission assignment."""

    __tablename__ = "auth_role_permissions"
    __table_args__ = (
        UniqueConstraint("role_id", "permission_id"),
        Index("ix_auth_role_permissions_role_permission", "role_id", "permission_id"),
    )

    role_id: Mapped[UUID] = mapped_column(ForeignKey("auth_roles.id"), primary_key=True)
    permission_id: Mapped[UUID] = mapped_column(ForeignKey("auth_permissions.id"), primary_key=True)

    role: Mapped[Role] = relationship(back_populates="permissions")
    permission: Mapped[Permission] = relationship()

