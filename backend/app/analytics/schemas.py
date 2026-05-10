"""Schemas and DTOs for SOC analytics APIs."""

from datetime import UTC, datetime, timedelta
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.ai.schemas import AIAnalyticsSummary
from app.events.schemas import NormalizedEvent
from app.events.taxonomy import EventCategory, EventSeverity
from app.threats.schemas import ThreatSummary


class TrendBucket(StrEnum):
    """Supported aggregation bucket sizes."""

    HOUR = "hour"
    DAY = "day"


class AnalyticsFilter(BaseModel):
    """Validated analytics filter boundary for event aggregations."""

    model_config = ConfigDict(extra="forbid")

    start_time: datetime = Field(default_factory=lambda: datetime.now(UTC) - timedelta(days=7))
    end_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str | None = Field(default=None, min_length=1, max_length=80)
    source: str | None = Field(default=None, min_length=1, max_length=120)
    category: EventCategory | None = None
    severity: EventSeverity | None = None
    bucket: TrendBucket = TrendBucket.DAY
    limit: int = Field(default=25, ge=1, le=100)
    offset: int = Field(default=0, ge=0, le=10_000)

    @model_validator(mode="after")
    def validate_time_range(self) -> "AnalyticsFilter":
        """Reject inverted or excessive query windows."""
        if self.end_time <= self.start_time:
            msg = "end_time must be after start_time"
            raise ValueError(msg)
        if self.end_time - self.start_time > timedelta(days=366):
            msg = "time range must not exceed 366 days"
            raise ValueError(msg)
        return self


class EventSearchFilters(BaseModel):
    """Validated normalized event retrieval filters for investigations."""

    model_config = ConfigDict(extra="forbid")

    start_time: datetime = Field(default_factory=lambda: datetime.now(UTC) - timedelta(days=7))
    end_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str | None = Field(default=None, min_length=1, max_length=80)
    source: str | None = Field(default=None, min_length=1, max_length=120)
    source_product: str | None = Field(default=None, min_length=1, max_length=120)
    source_vendor: str | None = Field(default=None, min_length=1, max_length=120)
    category: EventCategory | None = None
    severity: EventSeverity | None = None
    title: str | None = Field(default=None, min_length=2, max_length=120)
    actor_username: str | None = Field(default=None, min_length=1, max_length=160)
    actor_email: str | None = Field(default=None, min_length=3, max_length=320)
    actor_ip: str | None = Field(default=None, min_length=3, max_length=80)
    asset_hostname: str | None = Field(default=None, min_length=1, max_length=160)
    asset_ip: str | None = Field(default=None, min_length=3, max_length=80)
    ioc_value: str | None = Field(default=None, min_length=3, max_length=320)
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0, le=10_000)

    @model_validator(mode="after")
    def validate_search_window(self) -> "EventSearchFilters":
        """Keep analyst event retrieval bounded and operationally predictable."""
        if self.end_time <= self.start_time:
            msg = "end_time must be after start_time"
            raise ValueError(msg)
        if self.end_time - self.start_time > timedelta(days=90):
            msg = "event search window must not exceed 90 days"
            raise ValueError(msg)
        return self


class EventSearchResponse(BaseModel):
    """Paginated normalized event search response."""

    items: list[NormalizedEvent]
    limit: int
    offset: int


class CountSummary(BaseModel):
    """Named count response item."""

    name: str
    count: int
    percentage: float


class TrendPoint(BaseModel):
    """Time-bucketed event count."""

    bucket_start: datetime
    count: int


class SourceMetric(BaseModel):
    """Event source volume and severity summary."""

    source: str
    total_events: int
    high_or_critical_events: int
    last_event_time: datetime | None


class OperationalKpis(BaseModel):
    """Prepared SOC KPI fields for operational dashboards.

    Incident and alert KPIs are placeholders until incident and alert lifecycle
    domains exist. They are represented as nullable values instead of fabricated
    metrics.
    """

    mtta_minutes: float | None = None
    mttr_minutes: float | None = None
    true_positive_rate: float | None = None
    false_positive_rate: float | None = None
    alert_volume: int | None = None
    high_severity_ratio: float
    authentication_failure_ratio: float
    events_per_source: float


class ExecutiveOperationalKpis(BaseModel):
    """Consolidated leadership-facing SOC KPI summary."""

    high_severity_ratio: float
    authentication_failure_ratio: float
    alert_closure_ratio: float
    open_alerts: int
    unassigned_open_alerts: int
    mtta_minutes: float | None = None
    mttr_minutes: float | None = None
    true_positive_rate: float | None = None
    detection_coverage_ratio: float | None = None
    silent_active_rules: int | None = None
    high_or_critical_threat_insights: int
    high_confidence_ai_anomalies: int


class AlertWorkflowKpis(BaseModel):
    """Persisted alert workflow KPIs for SOC reporting."""

    alert_volume: int
    open_alerts: int
    acknowledged_alerts: int
    closed_alerts: int
    high_or_critical_alerts: int
    unassigned_open_alerts: int
    oldest_open_alert_minutes: float | None = None
    mtta_minutes: float | None = None
    mttr_minutes: float | None = None
    true_positive_rate: float | None = None
    false_positive_rate: float | None = None


class ExecutiveSecuritySummary(BaseModel):
    """Executive-ready security posture summary."""

    posture: str
    risk_score: int
    summary: str
    primary_driver: str | None = None
    total_events: int
    high_or_critical_events: int
    alert_volume: int
    open_alerts: int
    high_or_critical_alerts: int
    threat_insights: int
    high_or_critical_threat_insights: int
    ai_anomalies: int
    high_confidence_ai_anomalies: int
    active_sources: int


class ReportingFinding(BaseModel):
    """Prioritized deterministic reporting observation."""

    name: str
    severity: str
    count: int
    reason: str


class SocReport(BaseModel):
    """Executive and analyst-oriented SOC report."""

    period_start: datetime
    period_end: datetime
    executive_summary: ExecutiveSecuritySummary
    operational_kpis: OperationalKpis
    alert_workflow: AlertWorkflowKpis
    executive_kpis: ExecutiveOperationalKpis
    severity_distribution: list[CountSummary]
    category_distribution: list[CountSummary]
    top_sources: list[SourceMetric]
    threat_summary: ThreatSummary
    ai_summary: AIAnalyticsSummary
    findings: list[ReportingFinding]


class SocOverview(BaseModel):
    """Dashboard-ready SOC analytics overview."""

    total_events: int
    severity_distribution: list[CountSummary]
    category_distribution: list[CountSummary]
    ingestion_trend: list[TrendPoint]
    authentication_failures: list[TrendPoint]
    top_sources: list[SourceMetric]
    kpis: OperationalKpis
