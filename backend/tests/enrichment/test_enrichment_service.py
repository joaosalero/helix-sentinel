"""IOC enrichment service tests."""

from datetime import UTC, datetime
from uuid import uuid4

from app.audit.repositories import InMemoryAuditRepository
from app.audit.service import AuditService
from app.enrichment.repositories import InMemoryIOCRepository
from app.enrichment.schemas import EnrichmentExecutionRequest, IOCCreateRequest, IOCListFilters
from app.enrichment.service import IOCEnrichmentService
from app.enrichment.taxonomy import EnrichmentStatus, IndicatorType
from app.events.schemas import NormalizedActor, NormalizedEvent
from app.events.taxonomy import EventCategory, EventSeverity


def _event() -> NormalizedEvent:
    now = datetime(2026, 5, 8, 12, tzinfo=UTC)
    return NormalizedEvent(
        id=uuid4(),
        raw_event_id=uuid4(),
        tenant_id="tenant-a",
        source_name="edr",
        source_product=None,
        source_vendor=None,
        category=EventCategory.ENDPOINT,
        severity=EventSeverity.HIGH,
        event_time=now,
        ingested_at=now,
        title="suspicious process beacon",
        actor=NormalizedActor(ip_address="203.0.113.10"),
        ioc={"domain": "evil.example"},
    )


async def test_ioc_creation_normalizes_and_audits() -> None:
    audit = InMemoryAuditRepository()
    service = IOCEnrichmentService(
        InMemoryIOCRepository(),
        events=[],
        audit=AuditService(audit),
    )

    record = await service.create_ioc(
        IOCCreateRequest(
            indicator_type=IndicatorType.DOMAIN,
            value="Evil.Example.",
            source_name="internal-curation",
            tags=["Threat", " threat "],
        ),
        actor_id=None,
        actor_email=None,
        correlation_id="corr-ioc",
    )

    assert record.value == "evil.example"
    assert record.tags == ["threat"]
    assert audit.events[-1].action == "enrichment.ioc_created"
    assert audit.events[-1].metadata["indicator_type"] == "domain"


async def test_enrichment_matches_events_and_returns_explainability() -> None:
    audit = InMemoryAuditRepository()
    repository = InMemoryIOCRepository()
    event = _event()
    service = IOCEnrichmentService(repository, events=[event], audit=AuditService(audit))
    await service.create_ioc(
        IOCCreateRequest(
            indicator_type=IndicatorType.IP,
            value="203.0.113.10",
            confidence=80,
            severity="high",
            source_name="internal-curation",
            source_reliability="high",
        ),
        actor_id=None,
        actor_email=None,
        correlation_id=None,
    )

    response = await service.enrich_events(
        EnrichmentExecutionRequest(tenant_id="tenant-a"),
        actor_id=None,
        actor_email=None,
        correlation_id="corr-enrich",
    )

    assert response.status == EnrichmentStatus.MATCHED
    assert response.matched_events == 1
    assert response.total_matches == 1
    assert response.matches[0].matched_fields == ["actor.ip_address"]
    assert response.matches[0].confidence_factors
    assert audit.events[-1].action == "enrichment.executed"


async def test_ioc_filters_and_pagination_are_bounded() -> None:
    service = IOCEnrichmentService(
        InMemoryIOCRepository(),
        events=[],
        audit=AuditService(InMemoryAuditRepository()),
    )
    for index in range(3):
        await service.create_ioc(
            IOCCreateRequest(
                indicator_type=IndicatorType.DOMAIN,
                value=f"host{index}.example",
                confidence=40 + index * 20,
                severity="medium",
                source_name="source-a",
                tags=["malware"] if index else ["phishing"],
            ),
            actor_id=None,
            actor_email=None,
            correlation_id=None,
        )

    response = await service.list_iocs(
        IOCListFilters(tag="malware", min_confidence=50, limit=1, offset=0)
    )

    assert response.total == 2
    assert len(response.items) == 1
    assert response.items[0].confidence == 80
