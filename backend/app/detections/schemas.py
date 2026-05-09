"""Schemas for Detection Engineering APIs and services."""

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.detections.taxonomy import (
    DetectionCategory,
    DetectionRuleType,
    DetectionSeverity,
    DetectionStatus,
)

MAX_SIGMA_BYTES = 128 * 1024


class AttackTechnique(BaseModel):
    """Normalized MITRE ATT&CK technique reference."""

    technique_id: str = Field(pattern=r"^T\d{4}(?:\.\d{3})?$")
    name: str | None = Field(default=None, max_length=160)
    tactic: str | None = Field(default=None, max_length=120)


class DetectionRuleMetadata(BaseModel):
    """Operational detection metadata used by analytics and reviews."""

    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    false_positives: list[str] = Field(default_factory=list)
    author: str | None = Field(default=None, max_length=160)
    license: str | None = Field(default=None, max_length=120)
    operational_notes: str | None = Field(default=None, max_length=2000)
    tuning_metadata: dict[str, Any] = Field(default_factory=dict)
    quality_metadata: dict[str, Any] = Field(default_factory=dict)


class DetectionRule(BaseModel):
    """Normalized detection rule representation."""

    id: UUID
    title: str
    description: str | None
    rule_type: DetectionRuleType = DetectionRuleType.SIGMA
    status: DetectionStatus = DetectionStatus.DRAFT
    severity: DetectionSeverity
    category: DetectionCategory
    source: str | None = None
    sigma_id: str | None = None
    sigma_status: str | None = None
    raw_rule: dict[str, Any]
    detection: dict[str, Any]
    metadata: DetectionRuleMetadata
    attack: list[AttackTechnique]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SigmaRuleImportRequest(BaseModel):
    """Sigma upload request using text content instead of file execution."""

    model_config = ConfigDict(extra="forbid")

    content: str = Field(min_length=1, max_length=MAX_SIGMA_BYTES)
    status: DetectionStatus = DetectionStatus.DRAFT
    operational_notes: str | None = Field(default=None, max_length=2000)


class DetectionRuleListFilters(BaseModel):
    """Validated rule listing filters."""

    status: DetectionStatus | None = None
    severity: DetectionSeverity | None = None
    category: DetectionCategory | None = None
    source: str | None = Field(default=None, min_length=1, max_length=160)
    title: str | None = Field(default=None, min_length=2, max_length=120)
    tag: str | None = Field(default=None, min_length=1, max_length=120)
    attack_technique: str | None = Field(default=None, pattern=r"^T\d{4}(?:\.\d{3})?$")
    limit: int = Field(default=25, ge=1, le=100)
    offset: int = Field(default=0, ge=0, le=10_000)


class DetectionRuleSummary(BaseModel):
    """List response item for detection rules."""

    id: UUID
    title: str
    status: DetectionStatus
    severity: DetectionSeverity
    category: DetectionCategory
    tags: list[str]
    attack_techniques: list[str]
    updated_at: datetime


class DetectionRuleListResponse(BaseModel):
    """Paginated detection rule list response."""

    items: list[DetectionRuleSummary]
    total: int
    limit: int
    offset: int


class DetectionCoverageFilters(BaseModel):
    """Validated detection coverage analytics filters."""

    model_config = ConfigDict(extra="forbid")

    start_time: datetime = Field(default_factory=lambda: datetime.now(UTC) - timedelta(days=30))
    end_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str | None = Field(default=None, min_length=1, max_length=80)
    limit: int = Field(default=10, ge=1, le=25)

    @model_validator(mode="after")
    def validate_coverage_window(self) -> "DetectionCoverageFilters":
        """Keep coverage analytics bounded to operational reporting windows."""
        if self.end_time <= self.start_time:
            msg = "end_time must be after start_time"
            raise ValueError(msg)
        if self.end_time - self.start_time > timedelta(days=180):
            msg = "coverage window must not exceed 180 days"
            raise ValueError(msg)
        return self


class AttackTechniqueCoverage(BaseModel):
    """ATT&CK technique coverage and alert activity."""

    technique_id: str
    name: str | None = None
    tactic: str | None = None
    rule_count: int
    active_rule_count: int
    alert_count: int
    high_or_critical_alerts: int


class AttackTacticCoverage(BaseModel):
    """ATT&CK tactic coverage summary."""

    tactic: str
    technique_count: int
    rule_count: int
    alert_count: int


class DetectionRuleEfficacy(BaseModel):
    """Rule-level alert efficacy summary for Detection Engineering review."""

    rule_id: UUID
    title: str
    status: DetectionStatus
    severity: DetectionSeverity
    category: DetectionCategory
    attack_techniques: list[str]
    alert_count: int
    high_or_critical_alerts: int
    open_alerts: int
    true_positive_alerts: int
    false_positive_alerts: int
    last_alert_time: datetime | None = None


class DetectionCoverageSummary(BaseModel):
    """Operational detection coverage and ATT&CK visibility summary."""

    period_start: datetime
    period_end: datetime
    total_rules: int
    active_rules: int
    mapped_rules: int
    unmapped_rules: int
    active_mapped_rules: int
    techniques_covered: int
    tactics_covered: int
    coverage_ratio: float
    alerting_rules: int
    silent_active_rules: int
    total_alerts: int
    true_positive_rate: float | None = None
    false_positive_rate: float | None = None
    top_techniques: list[AttackTechniqueCoverage]
    tactic_coverage: list[AttackTacticCoverage]
    noisy_rules: list[DetectionRuleEfficacy]
    silent_rules: list[DetectionRuleEfficacy]


class DetectionExecutionRequest(BaseModel):
    """Bounded execution request for evaluating one active rule over events."""

    model_config = ConfigDict(extra="forbid")

    start_time: datetime = Field(default_factory=lambda: datetime.now(UTC) - timedelta(days=1))
    end_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str | None = Field(default=None, min_length=1, max_length=80)
    source: str | None = Field(default=None, min_length=1, max_length=120)
    limit: int = Field(default=500, ge=1, le=2_000)

    @model_validator(mode="after")
    def validate_execution_window(self) -> "DetectionExecutionRequest":
        """Keep synchronous rule execution bounded for API use."""
        if self.end_time <= self.start_time:
            msg = "end_time must be after start_time"
            raise ValueError(msg)
        if self.end_time - self.start_time > timedelta(days=30):
            msg = "execution window must not exceed 30 days"
            raise ValueError(msg)
        return self


class DetectionExecutionMatch(BaseModel):
    """Matched normalized event summary for a detection execution."""

    event_id: UUID
    tenant_id: str
    source_name: str
    event_time: datetime
    severity: str
    category: str
    title: str
    matched_selections: list[str]


class DetectionAlertStatus(StrEnum):
    """Operational lifecycle state for persisted detection alerts."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"


class DetectionAlert(BaseModel):
    """Durable alert state created from a detection execution match."""

    id: UUID = Field(default_factory=uuid4)
    tenant_id: str = Field(min_length=1, max_length=80)
    rule_id: UUID
    event_id: UUID
    status: DetectionAlertStatus = DetectionAlertStatus.OPEN
    severity: DetectionSeverity
    category: DetectionCategory
    title: str = Field(max_length=240)
    source_name: str = Field(max_length=120)
    event_time: datetime
    matched_selections: list[str] = Field(default_factory=list)
    correlation_id: str | None = Field(default=None, max_length=80)
    assigned_to: UUID | None = None
    acknowledged_at: datetime | None = None
    closed_at: datetime | None = None
    disposition: str | None = Field(default=None, max_length=120)
    investigation_note: str | None = Field(default=None, max_length=2000)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class DetectionAlertListFilters(BaseModel):
    """Validated alert listing filters for analyst queues."""

    status: DetectionAlertStatus | None = None
    severity: DetectionSeverity | None = None
    category: DetectionCategory | None = None
    source: str | None = Field(default=None, min_length=1, max_length=120)
    rule_id: UUID | None = None
    event_id: UUID | None = None
    assigned_to: UUID | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    tenant_id: str | None = Field(default=None, min_length=1, max_length=80)
    limit: int = Field(default=25, ge=1, le=100)
    offset: int = Field(default=0, ge=0, le=10_000)

    @model_validator(mode="after")
    def validate_event_time_range(self) -> "DetectionAlertListFilters":
        """Reject inverted or excessive alert event-time windows."""
        if self.start_time is None or self.end_time is None:
            return self
        if self.end_time <= self.start_time:
            msg = "end_time must be after start_time"
            raise ValueError(msg)
        if self.end_time - self.start_time > timedelta(days=90):
            msg = "alert search window must not exceed 90 days"
            raise ValueError(msg)
        return self


class DetectionAlertListResponse(BaseModel):
    """Paginated alert queue response."""

    items: list[DetectionAlert]
    total: int
    limit: int
    offset: int


class DetectionAlertWorkflowUpdateRequest(BaseModel):
    """Alert investigation state transition request."""

    model_config = ConfigDict(extra="forbid")

    status: DetectionAlertStatus
    disposition: str | None = Field(default=None, max_length=120)
    investigation_note: str | None = Field(default=None, max_length=2000)


class DetectionExecutionResponse(BaseModel):
    """Synchronous detection execution summary."""

    rule_id: UUID
    rule_title: str
    rule_status: DetectionStatus
    evaluated_events: int
    matched_events: int
    matches: list[DetectionExecutionMatch]
    executed_at: datetime


class SigmaParseResult(BaseModel):
    """Internal Sigma parse output before persistence."""

    title: str
    description: str | None
    severity: DetectionSeverity
    category: DetectionCategory
    source: str | None
    sigma_id: str | None
    sigma_status: str | None
    raw_rule: dict[str, Any]
    detection: dict[str, Any]
    metadata: DetectionRuleMetadata
    attack: list[AttackTechnique]

    @model_validator(mode="after")
    def require_detection_body(self) -> "SigmaParseResult":
        """Ensure a parsed rule has detection content."""
        if not self.detection:
            msg = "Sigma rule detection section must not be empty"
            raise ValueError(msg)
        return self
