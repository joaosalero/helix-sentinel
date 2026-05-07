"""Schemas for IOC enrichment APIs and services."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.enrichment.taxonomy import (
    EnrichmentStatus,
    IndicatorType,
    IOCSeverity,
    SourceReliability,
)
from app.enrichment.validators import normalize_indicator_value


class ConfidenceFactor(BaseModel):
    """Explainable IOC confidence scoring contribution."""

    name: str
    points: int
    reason: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class IOCCreateRequest(BaseModel):
    """Create request for locally managed IOCs."""

    model_config = ConfigDict(extra="forbid")

    indicator_type: IndicatorType
    value: str = Field(min_length=1, max_length=500)
    confidence: int = Field(default=50, ge=0, le=100)
    severity: IOCSeverity = IOCSeverity.MEDIUM
    source_name: str = Field(min_length=1, max_length=160)
    source_reliability: SourceReliability = SourceReliability.MEDIUM
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    tags: list[str] = Field(default_factory=list, max_length=25)
    notes: str | None = Field(default=None, max_length=2000)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("value")
    @classmethod
    def strip_value(cls, value: str) -> str:
        """Remove harmless surrounding whitespace before model-level validation."""
        return value.strip()

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, value: list[str]) -> list[str]:
        """Normalize tags for stable filtering."""
        return sorted({tag.strip().lower() for tag in value if tag.strip()})

    @model_validator(mode="after")
    def validate_indicator(self) -> "IOCCreateRequest":
        """Validate IOC syntax and temporal constraints."""
        self.value = normalize_indicator_value(self.indicator_type, self.value)
        if self.last_seen < self.first_seen:
            msg = "last_seen must be after or equal to first_seen"
            raise ValueError(msg)
        if self.expires_at is not None and self.expires_at <= self.first_seen:
            msg = "expires_at must be after first_seen"
            raise ValueError(msg)
        return self


class IOCRecord(BaseModel):
    """Stored IOC representation."""

    id: UUID
    indicator_type: IndicatorType
    value: str
    confidence: int
    severity: IOCSeverity
    source_name: str
    source_reliability: SourceReliability
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None
    tags: list[str]
    notes: str | None
    metadata: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class IOCListFilters(BaseModel):
    """Validated IOC listing filters."""

    indicator_type: IndicatorType | None = None
    severity: IOCSeverity | None = None
    source_name: str | None = Field(default=None, min_length=1, max_length=160)
    tag: str | None = Field(default=None, min_length=1, max_length=120)
    min_confidence: int = Field(default=0, ge=0, le=100)
    active_only: bool = True
    limit: int = Field(default=25, ge=1, le=100)
    offset: int = Field(default=0, ge=0, le=10_000)


class IOCListResponse(BaseModel):
    """Paginated IOC listing response."""

    items: list[IOCRecord]
    total: int
    limit: int
    offset: int


class EventIOCMatch(BaseModel):
    """Event-to-IOC relationship produced by deterministic enrichment."""

    event_id: UUID
    ioc_id: UUID
    indicator_type: IndicatorType
    value: str
    status: EnrichmentStatus
    confidence: int
    confidence_factors: list[ConfidenceFactor]
    matched_fields: list[str]
    metadata: dict[str, Any] = Field(default_factory=dict)


class EnrichmentExecutionRequest(BaseModel):
    """Request for deterministic IOC matching over normalized events."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str | None = Field(default=None, min_length=1, max_length=80)
    min_confidence: int = Field(default=0, ge=0, le=100)
    limit: int = Field(default=100, ge=1, le=500)


class EnrichmentExecutionResponse(BaseModel):
    """Summary of deterministic IOC enrichment execution."""

    status: EnrichmentStatus
    matched_events: int
    total_matches: int
    matches: list[EventIOCMatch]


class EnrichmentSummary(BaseModel):
    """Dashboard-ready enrichment summary."""

    total_iocs: int
    active_iocs: int
    high_confidence_iocs: int
    expired_iocs: int
    sources: int
