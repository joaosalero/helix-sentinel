"""Schemas for Threat Analytics filtering and responses."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.threats.taxonomy import IndicatorType, RiskLevel, ThreatInsightType


class ThreatAnalyticsFilter(BaseModel):
    """Validated query boundary for threat analytics."""

    model_config = ConfigDict(extra="forbid")

    start_time: datetime = Field(default_factory=lambda: datetime.now(UTC) - timedelta(days=7))
    end_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str | None = Field(default=None, min_length=1, max_length=80)
    insight_type: ThreatInsightType | None = None
    min_risk_score: int = Field(default=0, ge=0, le=100)
    min_confidence: int = Field(default=0, ge=0, le=100)
    indicator_type: IndicatorType | None = None
    indicator_value: str | None = Field(default=None, min_length=1, max_length=500)
    limit: int = Field(default=25, ge=1, le=100)
    offset: int = Field(default=0, ge=0, le=10_000)

    @model_validator(mode="after")
    def validate_time_range(self) -> "ThreatAnalyticsFilter":
        """Keep correlation windows bounded and predictable."""
        if self.end_time <= self.start_time:
            msg = "end_time must be after start_time"
            raise ValueError(msg)
        if self.end_time - self.start_time > timedelta(days=90):
            msg = "time range must not exceed 90 days"
            raise ValueError(msg)
        return self


class IOCReference(BaseModel):
    """IOC reference associated with a threat insight."""

    indicator_type: IndicatorType
    value: str
    confidence: int = Field(default=50, ge=0, le=100)


class RiskFactor(BaseModel):
    """Explainable risk scoring factor."""

    name: str
    points: int
    reason: str


class TemporalMetadata(BaseModel):
    """Time-window metadata for a correlated pattern."""

    first_seen: datetime
    last_seen: datetime
    event_count: int
    window_minutes: int


class ThreatInsight(BaseModel):
    """Generated threat insight for SOC triage and analytics."""

    id: UUID
    insight_type: ThreatInsightType
    title: str
    description: str
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    related_event_ids: list[UUID]
    iocs: list[IOCReference] = Field(default_factory=list)
    temporal: TemporalMetadata
    risk_factors: list[RiskFactor]
    metadata: dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ThreatInsightListResponse(BaseModel):
    """Paginated threat insight response."""

    items: list[ThreatInsight]
    total: int
    limit: int
    offset: int


class ThreatSummary(BaseModel):
    """Dashboard-ready Threat Analytics summary."""

    total_insights: int
    high_or_critical: int
    ioc_related: int
    repeated_auth_failures: int
    suspicious_ip_reuse: int
    endpoint_repetition: int
    event_bursts: int
    max_risk_score: int
