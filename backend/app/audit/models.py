"""Audit persistence model for security-relevant events."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.users.models import Base


class AuditEvent(Base):
    """Append-oriented audit event ready for SIEM ingestion."""

    __tablename__ = "auth_audit_events"
    __table_args__ = (
        Index("ix_auth_audit_events_action_created", "action", "created_at"),
        Index("ix_auth_audit_events_actor", "actor_id"),
        Index("ix_auth_audit_events_correlation", "correlation_id"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    outcome: Mapped[str] = mapped_column(String(40), nullable=False)
    actor_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    actor_email_hash: Mapped[str | None] = mapped_column(String(128))
    resource: Mapped[str | None] = mapped_column(String(160))
    correlation_id: Mapped[str | None] = mapped_column(String(80))
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

