"""SQLAlchemy models for Detection Engineering metadata."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.users.models import Base


class DetectionRuleRecord(Base):
    """Normalized detection rule record prepared for analytics and review."""

    __tablename__ = "detection_rules_v2"
    __table_args__ = (
        UniqueConstraint("sigma_id", "title"),
        Index("ix_detection_rules_v2_status_severity", "status", "severity"),
        Index("ix_detection_rules_v2_category_updated", "category", "updated_at"),
        Index("ix_detection_rules_v2_tags_gin", "tags", postgresql_using="gin"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    rule_type: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    severity: Mapped[str] = mapped_column(String(40), nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    source: Mapped[str | None] = mapped_column(String(160))
    sigma_id: Mapped[str | None] = mapped_column(String(120))
    sigma_status: Mapped[str | None] = mapped_column(String(80))
    tags: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    references: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    false_positives: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    author: Mapped[str | None] = mapped_column(String(160))
    license: Mapped[str | None] = mapped_column(String(120))
    operational_notes: Mapped[str | None] = mapped_column(Text)
    raw_rule: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    detection: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    tuning_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    quality_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    attack_mappings: Mapped[list["DetectionAttackMappingRecord"]] = relationship(
        "app.detections.models.DetectionAttackMappingRecord",
        back_populates="rule",
    )


class DetectionAttackMappingRecord(Base):
    """Rule-to-ATT&CK mapping for future coverage analytics."""

    __tablename__ = "detection_attack_mappings"
    __table_args__ = (
        UniqueConstraint("rule_id", "technique_id"),
        Index("ix_detection_attack_mappings_technique", "technique_id"),
        Index("ix_detection_attack_mappings_tactic", "tactic"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    rule_id: Mapped[UUID] = mapped_column(ForeignKey("detection_rules_v2.id"), nullable=False)
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)
    technique_name: Mapped[str | None] = mapped_column(String(160))
    tactic: Mapped[str | None] = mapped_column(String(120))

    rule: Mapped[DetectionRuleRecord] = relationship(
        "app.detections.models.DetectionRuleRecord",
        back_populates="attack_mappings",
    )
