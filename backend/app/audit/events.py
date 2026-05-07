"""Structured audit event definitions for authentication and authorization."""

from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class AuditAction(StrEnum):
    """Security actions that should be observable by operations and SIEM tools."""

    LOGIN_SUCCEEDED = "auth.login_succeeded"
    LOGIN_FAILED = "auth.login_failed"
    TOKEN_REFRESHED = "auth.token_refreshed"  # noqa: S105  # nosec B105
    LOGOUT_REQUESTED = "auth.logout_requested"
    PERMISSION_DENIED = "auth.permission_denied"
    USER_STATE_REJECTED = "auth.user_state_rejected"
    EVENT_INGESTED = "events.ingested"
    EVENT_VALIDATION_FAILED = "events.validation_failed"
    DETECTION_RULE_IMPORTED = "detections.rule_imported"
    DETECTION_RULE_PARSE_FAILED = "detections.rule_parse_failed"
    IOC_CREATED = "enrichment.ioc_created"
    IOC_ENRICHMENT_EXECUTED = "enrichment.executed"


class AuditEventCreate(BaseModel):
    """Sanitized audit event payload.

    Metadata must not contain credentials, full tokens, password hashes, or raw
    authorization headers.
    """

    action: AuditAction
    outcome: str
    actor_id: UUID | None = None
    actor_email_hash: str | None = None
    resource: str | None = None
    correlation_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
