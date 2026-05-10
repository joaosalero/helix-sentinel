"""Event ingestion application service."""

import logging

from app.audit.events import AuditAction
from app.audit.service import AuditService
from app.events.normalizer import EventNormalizer
from app.events.repositories import EventRepository
from app.events.schemas import EventIngestRequest, EventIngestResponse

logger = logging.getLogger(__name__)


class EventIngestionService:
    """Validate, persist, normalize, and audit security events."""

    def __init__(
        self,
        repository: EventRepository,
        normalizer: EventNormalizer,
        audit: AuditService,
    ) -> None:
        self.repository = repository
        self.normalizer = normalizer
        self.audit = audit

    async def ingest(
        self,
        request: EventIngestRequest,
        *,
        correlation_id: str,
    ) -> EventIngestResponse:
        """Store raw telemetry and its normalized representation."""
        raw_event = await self.repository.store_raw(request, correlation_id=correlation_id)
        normalized = self.normalizer.normalize(request, raw_event.id)
        await self.repository.store_normalized(normalized)
        await self.audit.record(
            AuditAction.EVENT_INGESTED,
            "success",
            correlation_id=correlation_id,
            resource=str(normalized.id),
            metadata={
                "category": normalized.category.value,
                "severity": normalized.severity.value,
                "source": normalized.source_name,
                "tenant_id": normalized.tenant_id,
            },
        )
        logger.info(
            "Security event ingested",
            extra={
                "correlation_id": correlation_id,
                "category": normalized.category.value,
                "severity": normalized.severity.value,
                "source": normalized.source_name,
            },
        )
        return EventIngestResponse(
            raw_event_id=raw_event.id,
            normalized_event_id=normalized.id,
            category=normalized.category,
            severity=normalized.severity,
            correlation_id=correlation_id,
        )
