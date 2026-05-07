"""SQLAlchemy models for AI-assisted analytics metadata."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.users.models import Base


class AIAnomalyRecord(Base):
    """Persisted explainable anomaly metadata for future historical analytics."""

    __tablename__ = "ai_anomaly_findings"
    __table_args__ = (
        Index("ix_ai_anomaly_findings_type_generated", "anomaly_type", "generated_at"),
        Index("ix_ai_anomaly_findings_score_generated", "score", "generated_at"),
        Index("ix_ai_anomaly_findings_temporal", "first_seen", "last_seen"),
        Index("ix_ai_anomaly_findings_metadata_gin", "metadata", postgresql_using="gin"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    anomaly_type: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    confidence: Mapped[str] = mapped_column(String(40), nullable=False)
    event_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    factors: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )


class AIEnrichmentRecord(Base):
    """Persisted deterministic enrichment metadata for normalized events."""

    __tablename__ = "ai_event_enrichments"
    __table_args__ = (
        Index("ix_ai_event_enrichments_event", "event_id"),
        Index("ix_ai_event_enrichments_score", "score"),
        Index(
            "ix_ai_event_enrichments_classifications_gin",
            "classifications",
            postgresql_using="gin",
        ),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    event_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    keywords: Mapped[list[str]] = mapped_column(JSONB, default=list)
    suspicious_terms: Mapped[list[str]] = mapped_column(JSONB, default=list)
    classifications: Mapped[list[str]] = mapped_column(JSONB, default=list)
    confidence: Mapped[str] = mapped_column(String(40), nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    factors: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
