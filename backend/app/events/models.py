"""SQLAlchemy models for raw and normalized security events."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.users.models import Base


class EventSource(Base):
    """Registered source metadata for ingestion and filtering."""

    __tablename__ = "event_sources"
    __table_args__ = (UniqueConstraint("tenant_id", "name", "product", "vendor"),)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    product: Mapped[str | None] = mapped_column(String(120))
    vendor: Mapped[str | None] = mapped_column(String(120))
    environment: Mapped[str | None] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )


class RawSecurityEvent(Base):
    """Raw JSON security event retained for auditability and reprocessing."""

    __tablename__ = "raw_security_events"
    __table_args__ = (
        Index("ix_raw_security_events_tenant_received", "tenant_id", "received_at"),
        Index("ix_raw_security_events_source_received", "source_name", "received_at"),
        Index("ix_raw_security_events_payload_gin", "payload", postgresql_using="gin"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    source_name: Mapped[str] = mapped_column(String(120), nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(160))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    correlation_id: Mapped[str] = mapped_column(String(80), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(20), nullable=False, default="v1")

    normalized_events: Mapped[list["NormalizedSecurityEvent"]] = relationship(
        back_populates="raw_event"
    )


class NormalizedSecurityEvent(Base):
    """Normalized security event optimized for analytics and detection queries."""

    __tablename__ = "normalized_security_events"
    __table_args__ = (
        Index("ix_normalized_events_tenant_time", "tenant_id", "event_time"),
        Index("ix_normalized_events_category_time", "category", "event_time"),
        Index("ix_normalized_events_severity_time", "severity", "event_time"),
        Index("ix_normalized_events_source_time", "source_name", "event_time"),
        Index("ix_normalized_events_actor_gin", "actor", postgresql_using="gin"),
        Index("ix_normalized_events_asset_gin", "asset", postgresql_using="gin"),
        Index("ix_normalized_events_enrichment_gin", "enrichment", postgresql_using="gin"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    raw_event_id: Mapped[UUID] = mapped_column(ForeignKey("raw_security_events.id"), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    source_name: Mapped[str] = mapped_column(String(120), nullable=False)
    source_product: Mapped[str | None] = mapped_column(String(120))
    source_vendor: Mapped[str | None] = mapped_column(String(120))
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    severity: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    actor: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    asset: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    network: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    ioc: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    enrichment: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    normalization_version: Mapped[str] = mapped_column(String(20), nullable=False)

    raw_event: Mapped[RawSecurityEvent] = relationship(back_populates="normalized_events")
