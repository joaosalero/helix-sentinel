"""SQLAlchemy models for Threat Analytics persistence readiness."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.users.models import Base


class ThreatInsightRecord(Base):
    """Persisted threat insight prepared for historical analytics."""

    __tablename__ = "threat_insights"
    __table_args__ = (
        Index("ix_threat_insights_type_generated", "insight_type", "generated_at"),
        Index("ix_threat_insights_risk_generated", "risk_score", "generated_at"),
        Index("ix_threat_insights_temporal", "first_seen", "last_seen"),
        Index("ix_threat_insights_metadata_gin", "metadata", postgresql_using="gin"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    insight_type: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(40), nullable=False)
    related_event_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    risk_factors: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    iocs: Mapped[list["ThreatIOCReferenceRecord"]] = relationship(back_populates="insight")


class ThreatIOCReferenceRecord(Base):
    """IOC reference linked to a threat insight."""

    __tablename__ = "threat_ioc_references"
    __table_args__ = (
        Index("ix_threat_ioc_references_type_value", "indicator_type", "value"),
        Index("ix_threat_ioc_references_confidence", "confidence"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    insight_id: Mapped[UUID] = mapped_column(ForeignKey("threat_insights.id"), nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(40), nullable=False)
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)

    insight: Mapped[ThreatInsightRecord] = relationship(back_populates="iocs")

