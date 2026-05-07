"""Schemas for Detection Engineering APIs and services."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

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

