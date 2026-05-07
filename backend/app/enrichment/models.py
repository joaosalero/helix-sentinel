"""SQLAlchemy models for IOC enrichment persistence readiness."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.users.models import Base


class IOCIndicatorRecord(Base):
    """Managed IOC record used for deterministic local enrichment."""

    __tablename__ = "ioc_indicators"
    __table_args__ = (
        UniqueConstraint("indicator_type", "value", name="uq_ioc_indicators_type_value"),
        Index("ix_ioc_indicators_type", "indicator_type"),
        Index("ix_ioc_indicators_confidence", "confidence"),
        Index("ix_ioc_indicators_source", "source_name"),
        Index("ix_ioc_indicators_seen", "first_seen", "last_seen"),
        Index("ix_ioc_indicators_expires", "expires_at"),
        Index("ix_ioc_indicators_tags_gin", "tags", postgresql_using="gin"),
        Index("ix_ioc_indicators_metadata_gin", "metadata", postgresql_using="gin"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    indicator_type: Mapped[str] = mapped_column(String(40), nullable=False)
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    severity: Mapped[str] = mapped_column(String(40), nullable=False)
    source_name: Mapped[str] = mapped_column(String(160), nullable=False)
    source_reliability: Mapped[str] = mapped_column(String(40), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    notes: Mapped[str | None] = mapped_column(String(2000))
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    matches: Mapped[list["EventIOCMatchRecord"]] = relationship(back_populates="ioc")


class EventIOCMatchRecord(Base):
    """Event-to-IOC relationship with explainable enrichment metadata."""

    __tablename__ = "event_ioc_matches"
    __table_args__ = (
        UniqueConstraint("event_id", "ioc_id", name="uq_event_ioc_matches_event_ioc"),
        Index("ix_event_ioc_matches_event", "event_id"),
        Index("ix_event_ioc_matches_ioc", "ioc_id"),
        Index("ix_event_ioc_matches_status", "status"),
        Index("ix_event_ioc_matches_confidence", "confidence"),
        Index("ix_event_ioc_matches_created", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    event_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    ioc_id: Mapped[UUID] = mapped_column(ForeignKey("ioc_indicators.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
    matched_fields: Mapped[list[str]] = mapped_column(JSONB, default=list)
    confidence_factors: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    ioc: Mapped[IOCIndicatorRecord] = relationship(back_populates="matches")
