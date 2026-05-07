"""Schemas for event ingestion and normalized telemetry."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.events.taxonomy import EventCategory, EventSeverity

MAX_PAYLOAD_KEYS = 200
MAX_STRING_LENGTH = 4096


JsonObject = dict[str, Any]


class EventSourceInput(BaseModel):
    """Source metadata supplied by ingestion clients."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=2, max_length=120)
    product: str | None = Field(default=None, max_length=120)
    vendor: str | None = Field(default=None, max_length=120)
    environment: str | None = Field(default=None, max_length=80)


class EventIngestRequest(BaseModel):
    """Strict event ingestion request.

    Raw payloads must be JSON objects. Nested content is retained but bounded by
    basic validation to avoid accepting unreasonably large or ambiguous inputs.
    """

    model_config = ConfigDict(extra="forbid")

    source: EventSourceInput
    payload: JsonObject
    category: EventCategory | None = None
    severity: EventSeverity | None = None
    event_time: datetime | None = None
    external_id: str | None = Field(default=None, max_length=160)
    tenant_id: str = Field(default="default", min_length=1, max_length=80)

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: JsonObject) -> JsonObject:
        """Reject empty, oversized, or secret-shaped payloads."""
        if not value:
            msg = "payload must not be empty"
            raise ValueError(msg)
        if len(value) > MAX_PAYLOAD_KEYS:
            msg = "payload has too many top-level keys"
            raise ValueError(msg)
        _validate_json_value(value)
        return value

    @model_validator(mode="after")
    def normalize_event_time(self) -> "EventIngestRequest":
        """Use current UTC time when clients omit event time."""
        if self.event_time is None:
            self.event_time = datetime.now(UTC)
        return self


class NormalizedActor(BaseModel):
    """Actor fields commonly used in security analytics."""

    user_id: str | None = None
    username: str | None = None
    email: str | None = None
    ip_address: str | None = None


class NormalizedAsset(BaseModel):
    """Asset fields commonly used in endpoint and network telemetry."""

    asset_id: str | None = None
    hostname: str | None = None
    ip_address: str | None = None


class NormalizedEvent(BaseModel):
    """Normalized event representation stored for analytics queries."""

    id: UUID
    raw_event_id: UUID
    tenant_id: str
    source_name: str
    source_product: str | None
    source_vendor: str | None
    category: EventCategory
    severity: EventSeverity
    event_time: datetime
    ingested_at: datetime
    title: str
    actor: NormalizedActor = Field(default_factory=NormalizedActor)
    asset: NormalizedAsset = Field(default_factory=NormalizedAsset)
    network: JsonObject = Field(default_factory=dict)
    ioc: JsonObject = Field(default_factory=dict)
    enrichment: JsonObject = Field(default_factory=dict)
    normalization_version: str = "v1"


class EventIngestResponse(BaseModel):
    """Public response for successful ingestion."""

    raw_event_id: UUID
    normalized_event_id: UUID
    category: EventCategory
    severity: EventSeverity
    correlation_id: str


def _validate_json_value(value: Any, depth: int = 0) -> None:
    """Validate JSON-like values without unsafe deserialization or coercion."""
    if depth > 8:
        msg = "payload nesting is too deep"
        raise ValueError(msg)
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or not key:
                msg = "payload keys must be non-empty strings"
                raise ValueError(msg)
            if len(key) > 160:
                msg = "payload key is too long"
                raise ValueError(msg)
            _validate_json_value(nested, depth + 1)
        return
    if isinstance(value, list):
        if len(value) > 500:
            msg = "payload array is too large"
            raise ValueError(msg)
        for nested in value:
            _validate_json_value(nested, depth + 1)
        return
    if isinstance(value, str) and len(value) > MAX_STRING_LENGTH:
        msg = "payload string value is too long"
        raise ValueError(msg)
    if value is None or isinstance(value, bool | int | float | str):
        return
    msg = "payload contains unsupported JSON value"
    raise ValueError(msg)

