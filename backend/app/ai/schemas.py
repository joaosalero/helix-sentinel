"""Schemas for AI-assisted analytics outputs."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.ai.taxonomy import AnomalyType, ClassificationLabel, ConfidenceLevel
from app.events.taxonomy import EventCategory


class AIAnalyticsFilter(BaseModel):
    """Validated AI analytics query filters."""

    model_config = ConfigDict(extra="forbid")

    start_time: datetime = Field(default_factory=lambda: datetime.now(UTC) - timedelta(days=7))
    end_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str | None = Field(default=None, min_length=1, max_length=80)
    category: EventCategory | None = None
    anomaly_type: AnomalyType | None = None
    classification: ClassificationLabel | None = None
    min_score: int = Field(default=0, ge=0, le=100)
    limit: int = Field(default=25, ge=1, le=100)
    offset: int = Field(default=0, ge=0, le=10_000)

    @model_validator(mode="after")
    def validate_time_range(self) -> "AIAnalyticsFilter":
        """Keep deterministic scoring windows operationally bounded."""
        if self.end_time <= self.start_time:
            msg = "end_time must be after start_time"
            raise ValueError(msg)
        if self.end_time - self.start_time > timedelta(days=90):
            msg = "time range must not exceed 90 days"
            raise ValueError(msg)
        return self


class ExplainabilityFactor(BaseModel):
    """Transparent scoring contribution."""

    name: str
    points: int
    reason: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AnomalyFinding(BaseModel):
    """Explainable anomaly finding generated from normalized events."""

    id: UUID
    anomaly_type: AnomalyType
    title: str
    score: int = Field(ge=0, le=100)
    confidence: ConfidenceLevel
    event_ids: list[UUID]
    category: EventCategory
    first_seen: datetime
    last_seen: datetime
    factors: list[ExplainabilityFactor]
    metadata: dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AIEnrichment(BaseModel):
    """Deterministic NLP/classification enrichment for one event."""

    event_id: UUID
    keywords: list[str]
    suspicious_terms: list[str]
    classifications: list[ClassificationLabel]
    confidence: ConfidenceLevel
    score: int = Field(ge=0, le=100)
    factors: list[ExplainabilityFactor]


class AnomalyListResponse(BaseModel):
    """Paginated anomaly response."""

    items: list[AnomalyFinding]
    total: int
    limit: int
    offset: int


class EnrichmentListResponse(BaseModel):
    """Paginated enrichment response."""

    items: list[AIEnrichment]
    total: int
    limit: int
    offset: int


class AIAnalyticsSummary(BaseModel):
    """Dashboard-ready AI analytics summary."""

    total_anomalies: int
    high_confidence: int
    max_score: int
    suspicious_classifications: int
    enriched_events: int

