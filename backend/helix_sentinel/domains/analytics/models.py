"""Analytics pipeline and AI enrichment metadata models."""

from typing import Any

from sqlalchemy import Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from helix_sentinel.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AnalyticsPipeline(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Analytics pipeline definition for scoring, classification, or enrichment."""

    __tablename__ = "analytics_pipelines"
    __table_args__ = (Index("ix_analytics_pipelines_type_status", "pipeline_type", "status"),)

    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    pipeline_type: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="draft")
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    explainability_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class AIEnrichment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """AI-assisted enrichment output with prompt-injection-aware metadata."""

    __tablename__ = "ai_enrichments"
    __table_args__ = (
        Index("ix_ai_enrichments_entity", "entity_type", "entity_id"),
        Index("ix_ai_enrichments_metadata_gin", "metadata", postgresql_using="gin"),
    )

    entity_type: Mapped[str] = mapped_column(String(120), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(120), nullable=False)
    model_provider: Mapped[str] = mapped_column(String(120), nullable=False)
    model_name: Mapped[str] = mapped_column(String(160), nullable=False)
    summary: Mapped[str] = mapped_column(String(2000), nullable=False)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict)

