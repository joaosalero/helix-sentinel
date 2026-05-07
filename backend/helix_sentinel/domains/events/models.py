"""Security event persistence models optimized for analytics queries."""

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from helix_sentinel.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class SecurityEvent(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Normalized security event with raw JSONB context retained."""

    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_source_time", "source", "event_time"),
        Index("ix_security_events_tenant_time", "tenant_id", "event_time"),
        Index("ix_security_events_payload_gin", "payload", postgresql_using="gin"),
    )

    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(120), nullable=False)
    event_type: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(40), nullable=False)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    normalized: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

