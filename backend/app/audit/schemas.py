"""Schemas for operational audit activity analytics."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AuditActivityFilter(BaseModel):
    """Validated audit activity aggregation filter."""

    model_config = ConfigDict(extra="forbid")

    start_time: datetime = Field(default_factory=lambda: datetime.now(UTC) - timedelta(days=7))
    end_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str | None = Field(default=None, min_length=1, max_length=80)
    limit: int = Field(default=10, ge=1, le=50)
    offset: int = Field(default=0, ge=0, le=1_000)

    @model_validator(mode="after")
    def validate_time_range(self) -> "AuditActivityFilter":
        if self.end_time <= self.start_time:
            msg = "end_time must be after start_time"
            raise ValueError(msg)
        if self.end_time - self.start_time > timedelta(days=90):
            msg = "audit activity window must not exceed 90 days"
            raise ValueError(msg)
        return self


class AuditActionMetric(BaseModel):
    """Audit action/outcome count for operational oversight."""

    action: str
    outcome: str
    count: int
    last_seen: datetime | None = None


class AuditActorMetric(BaseModel):
    """Actor activity count without exposing raw identity attributes."""

    actor_id: UUID | None = None
    actor_email_hash: str | None = None
    count: int
    failure_count: int
    last_seen: datetime | None = None


class RecentAuditActivity(BaseModel):
    """Bounded recent audit event surface for SOC oversight."""

    action: str
    outcome: str
    resource: str | None = None
    correlation_id: str | None = None
    created_at: datetime | None = None


class SecurityActivityFinding(BaseModel):
    """Deterministic operational audit observation."""

    name: str
    severity: str
    count: int
    reason: str


class AuthenticationActivitySummary(BaseModel):
    """Authentication audit outcomes for operational security review."""

    successes: int
    failures: int
    token_refreshes: int
    logouts: int
    user_state_rejections: int
    failure_ratio: float


class AuthorizationActivitySummary(BaseModel):
    """Authorization audit outcomes for access oversight."""

    permission_denials: int
    tenant_scope_denials: int


class InvestigationActivitySummary(BaseModel):
    """Alert investigation workflow audit outcomes."""

    workflow_updates: int
    acknowledgements: int
    closures: int


class SecurityActivitySummary(BaseModel):
    """Repository-backed security activity aggregate."""

    period_start: datetime
    period_end: datetime
    total_audit_events: int
    successful_authentications: int
    failed_authentications: int
    permission_denials: int
    tenant_scope_denials: int
    investigation_updates: int
    detection_rule_activity: int
    event_ingestion_rejections: int
    active_actor_count: int
    authentication: AuthenticationActivitySummary
    authorization: AuthorizationActivitySummary
    investigations: InvestigationActivitySummary
    actions: list[AuditActionMetric]
    top_actors: list[AuditActorMetric]
    recent_activity: list[RecentAuditActivity]
    findings: list[SecurityActivityFinding]
