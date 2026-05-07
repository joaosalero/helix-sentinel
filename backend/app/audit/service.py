"""Audit logging service with secret-safe metadata handling."""

import hashlib
import logging
from typing import Any
from uuid import UUID

from app.audit.events import AuditAction, AuditEventCreate
from app.audit.repositories import AuditRepository

logger = logging.getLogger(__name__)

SENSITIVE_METADATA_KEYS = {"password", "token", "refresh_token", "access_token", "authorization"}


class AuditService:
    """Create structured security audit events without leaking secrets."""

    def __init__(self, repository: AuditRepository) -> None:
        self.repository = repository

    async def record(
        self,
        action: AuditAction,
        outcome: str,
        *,
        actor_id: UUID | None = None,
        actor_email: str | None = None,
        resource: str | None = None,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Persist a sanitized audit event and emit an operational log line."""
        event = AuditEventCreate(
            action=action,
            outcome=outcome,
            actor_id=actor_id,
            actor_email_hash=_hash_actor_email(actor_email),
            resource=resource,
            correlation_id=correlation_id,
            metadata=_sanitize_metadata(metadata or {}),
        )
        await self.repository.append(event)
        logger.info(
            "Security audit event",
            extra={
                "action": action.value,
                "outcome": outcome,
                "correlation_id": correlation_id,
                "actor_id": str(actor_id) if actor_id else None,
            },
        )


def _hash_actor_email(email: str | None) -> str | None:
    if email is None:
        return None
    return hashlib.sha256(email.lower().encode("utf-8")).hexdigest()


def _sanitize_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """Remove secret-like metadata keys before audit persistence."""
    sanitized: dict[str, Any] = {}
    for key, value in metadata.items():
        if key.lower() in SENSITIVE_METADATA_KEYS:
            sanitized[key] = "[redacted]"
        else:
            sanitized[key] = value
    return sanitized

