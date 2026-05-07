"""Append-oriented audit event model."""

from typing import Any

from sqlalchemy import Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from helix_sentinel.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AuditEvent(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Security-relevant audit event.

    Audit payloads must be sanitized before persistence to avoid storing secrets,
    credentials, full tokens, or sensitive raw security telemetry unnecessarily.
    """

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_actor_action", "actor_id", "action"),
        Index("ix_audit_events_resource", "resource_type", "resource_id"),
    )

    actor_id: Mapped[str | None] = mapped_column(String(80), index=True)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(120))
    resource_id: Mapped[str | None] = mapped_column(String(120))
    outcome: Mapped[str] = mapped_column(String(40), nullable=False)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict)

