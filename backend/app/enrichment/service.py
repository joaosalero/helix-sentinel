"""Deterministic IOC enrichment service."""

import logging
from collections import defaultdict
from contextlib import suppress
from time import perf_counter
from uuid import UUID

from app.audit.events import AuditAction
from app.audit.service import AuditService
from app.enrichment.metrics import (
    ioc_created_total,
    ioc_enrichment_duration_seconds,
    ioc_matches_total,
)
from app.enrichment.repositories import IOCRepository
from app.enrichment.schemas import (
    EnrichmentExecutionRequest,
    EnrichmentExecutionResponse,
    EnrichmentSummary,
    EventIOCMatch,
    IOCCreateRequest,
    IOCListFilters,
    IOCListResponse,
    IOCRecord,
)
from app.enrichment.scoring import score_ioc_match
from app.enrichment.taxonomy import EnrichmentStatus, IndicatorType
from app.enrichment.validators import normalize_indicator_value
from app.events.schemas import NormalizedEvent

logger = logging.getLogger(__name__)


class IOCEnrichmentService:
    """Manage local IOCs and match them against normalized event metadata.

    This service intentionally performs only local deterministic matching. It
    does not fetch URLs, resolve domains, or call external reputation systems,
    which keeps the foundation SSRF-safe until explicit integrations exist.
    """

    def __init__(
        self,
        repository: IOCRepository,
        *,
        events: list[NormalizedEvent],
        audit: AuditService,
    ) -> None:
        self.repository = repository
        self.events = events
        self.audit = audit

    async def create_ioc(
        self,
        request: IOCCreateRequest,
        *,
        actor_id: UUID | None,
        actor_email: str | None,
        correlation_id: str | None,
    ) -> IOCRecord:
        """Create a validated IOC and emit a sanitized audit event."""
        record = await self.repository.create(request)
        ioc_created_total.labels(
            indicator_type=record.indicator_type.value,
            severity=record.severity.value,
        ).inc()
        await self.audit.record(
            AuditAction.IOC_CREATED,
            "success",
            actor_id=actor_id,
            actor_email=actor_email,
            resource=str(record.id),
            correlation_id=correlation_id,
            metadata={
                "indicator_type": record.indicator_type.value,
                "source_name": record.source_name,
                "confidence": record.confidence,
            },
        )
        return record

    async def list_iocs(self, filters: IOCListFilters) -> IOCListResponse:
        """Return filtered IOC records for SOC and Threat Analytics workflows."""
        items, total = await self.repository.list_iocs(filters)
        return IOCListResponse(items=items, total=total, limit=filters.limit, offset=filters.offset)

    async def get_ioc(self, ioc_id: UUID) -> IOCRecord | None:
        """Return a single IOC record by identifier."""
        return await self.repository.get(ioc_id)

    async def summary(self) -> EnrichmentSummary:
        """Return dashboard-ready IOC inventory metrics."""
        active = await self.repository.all_active()
        all_items = await self.repository.all_iocs()
        return EnrichmentSummary(
            total_iocs=len(all_items),
            active_iocs=len(active),
            high_confidence_iocs=sum(ioc.confidence >= 70 for ioc in all_items),
            expired_iocs=len(all_items) - len(active),
            sources=len({ioc.source_name for ioc in all_items}),
        )

    async def enrich_events(
        self,
        request: EnrichmentExecutionRequest,
        *,
        actor_id: UUID | None,
        actor_email: str | None,
        correlation_id: str | None,
    ) -> EnrichmentExecutionResponse:
        """Match normalized events against active IOCs without external lookups."""
        started = perf_counter()
        iocs = [
            ioc
            for ioc in await self.repository.all_active()
            if ioc.confidence >= request.min_confidence
        ]
        events = [
            event
            for event in self.events
            if request.tenant_id is None or event.tenant_id == request.tenant_id
        ][: request.limit]
        matches = _match_events(events, iocs)
        elapsed = perf_counter() - started
        ioc_enrichment_duration_seconds.observe(elapsed)
        for match in matches:
            ioc_matches_total.labels(indicator_type=match.indicator_type.value).inc()
        await self.repository.store_matches(matches)
        await self.audit.record(
            AuditAction.IOC_ENRICHMENT_EXECUTED,
            "success",
            actor_id=actor_id,
            actor_email=actor_email,
            correlation_id=correlation_id,
            metadata={
                "event_count": len(events),
                "match_count": len(matches),
                "elapsed_ms": round(elapsed * 1000, 2),
            },
        )
        logger.info(
            "IOC enrichment completed",
            extra={
                "correlation_id": correlation_id,
                "event_count": len(events),
                "match_count": len(matches),
                "elapsed_ms": round(elapsed * 1000, 2),
            },
        )
        return EnrichmentExecutionResponse(
            status=EnrichmentStatus.MATCHED if matches else EnrichmentStatus.NO_MATCH,
            matched_events=len({match.event_id for match in matches}),
            total_matches=len(matches),
            matches=matches,
        )


def _match_events(events: list[NormalizedEvent], iocs: list[IOCRecord]) -> list[EventIOCMatch]:
    iocs_by_key: dict[tuple[IndicatorType, str], list[IOCRecord]] = defaultdict(list)
    for ioc in iocs:
        iocs_by_key[(ioc.indicator_type, ioc.value)].append(ioc)

    matches: list[EventIOCMatch] = []
    for event in events:
        candidates = _extract_candidates(event)
        for key, fields in candidates.items():
            for ioc in iocs_by_key.get(key, []):
                confidence, factors = score_ioc_match(ioc, fields)
                matches.append(
                    EventIOCMatch(
                        event_id=event.id,
                        ioc_id=ioc.id,
                        indicator_type=ioc.indicator_type,
                        value=ioc.value,
                        status=EnrichmentStatus.MATCHED,
                        confidence=confidence,
                        confidence_factors=factors,
                        matched_fields=fields,
                        metadata={
                            "tenant_id": event.tenant_id,
                            "source_name": event.source_name,
                            "category": event.category.value,
                            "severity": event.severity.value,
                        },
                    )
                )
    matches.sort(key=lambda item: (item.confidence, item.event_id.hex), reverse=True)
    return matches


def _extract_candidates(event: NormalizedEvent) -> dict[tuple[IndicatorType, str], list[str]]:
    candidates: dict[tuple[IndicatorType, str], list[str]] = defaultdict(list)
    _add_candidate(candidates, IndicatorType.IP, event.actor.ip_address, "actor.ip_address")
    _add_candidate(candidates, IndicatorType.IP, event.asset.ip_address, "asset.ip_address")
    for field in ("source_ip", "destination_ip", "src_ip", "dst_ip"):
        _add_candidate(candidates, IndicatorType.IP, event.network.get(field), f"network.{field}")
    _add_ioc_candidates(candidates, event)
    return candidates


def _add_ioc_candidates(
    candidates: dict[tuple[IndicatorType, str], list[str]],
    event: NormalizedEvent,
) -> None:
    indicator_type = event.ioc.get("indicator_type") or event.ioc.get("type")
    indicator = event.ioc.get("indicator") or event.ioc.get("value")
    if isinstance(indicator_type, str) and isinstance(indicator, str):
        with suppress(ValueError):
            _add_candidate(candidates, IndicatorType(indicator_type), indicator, "ioc.indicator")
    for field, indicator_enum in {
        "domain": IndicatorType.DOMAIN,
        "url": IndicatorType.URL,
        "hash": IndicatorType.HASH,
        "file_hash": IndicatorType.HASH,
    }.items():
        _add_candidate(candidates, indicator_enum, event.ioc.get(field), f"ioc.{field}")


def _add_candidate(
    candidates: dict[tuple[IndicatorType, str], list[str]],
    indicator_type: IndicatorType,
    value: object,
    field: str,
) -> None:
    if not isinstance(value, str) or not value.strip():
        return
    try:
        normalized = normalize_indicator_value(indicator_type, value)
    except ValueError:
        return
    candidates[(indicator_type, normalized)].append(field)
