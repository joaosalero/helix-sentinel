"""Detection lifecycle persistence models."""

from typing import Any
from uuid import UUID

from sqlalchemy import ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from helix_sentinel.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class DetectionRule(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Versioned detection rule metadata and query content."""

    __tablename__ = "detection_rules"
    __table_args__ = (
        UniqueConstraint("slug", "version"),
        Index("ix_detection_rules_status_severity", "status", "severity"),
    )

    slug: Mapped[str] = mapped_column(String(160), nullable=False)
    name: Mapped[str] = mapped_column(String(240), nullable=False)
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="draft")
    severity: Mapped[str] = mapped_column(String(40), nullable=False)
    query_language: Mapped[str] = mapped_column(String(80), nullable=False)
    query: Mapped[str] = mapped_column(Text, nullable=False)
    mitre_attack: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict)

    tests: Mapped[list["DetectionTestCase"]] = relationship(back_populates="rule")


class DetectionTestCase(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Validation fixture for detection behavior."""

    __tablename__ = "detection_test_cases"

    rule_id: Mapped[UUID] = mapped_column(ForeignKey("detection_rules.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    fixture: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    expected_result: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    rule: Mapped[DetectionRule] = relationship(back_populates="tests")
