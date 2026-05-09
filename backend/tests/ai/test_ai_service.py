"""AI-assisted analytics service tests."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.ai.nlp import extract_keywords
from app.ai.repositories import InMemoryAIEventRepository
from app.ai.schemas import AIAnalyticsFilter
from app.ai.service import AIAnalyticsService
from app.ai.taxonomy import AnomalyType, ClassificationLabel
from app.events.schemas import NormalizedActor, NormalizedAsset, NormalizedEvent
from app.events.taxonomy import EventCategory, EventSeverity


def _event(
    index: int,
    event_time: datetime,
    *,
    source: str = "edr",
    category: EventCategory = EventCategory.ENDPOINT,
    severity: EventSeverity = EventSeverity.HIGH,
    title: str = "powershell encoded suspicious process",
    actor: str | None = None,
    asset: str | None = None,
    ioc: dict[str, object] | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        id=uuid4(),
        raw_event_id=uuid4(),
        tenant_id="tenant-a",
        source_name=source,
        source_product=None,
        source_vendor=None,
        category=category,
        severity=severity,
        event_time=event_time,
        ingested_at=event_time,
        title=title,
        actor=NormalizedActor(username=actor),
        asset=NormalizedAsset(hostname=asset or f"endpoint-{index % 2}"),
        ioc=ioc or {},
    )


@pytest.fixture
def ai_events() -> list[NormalizedEvent]:
    base = datetime(2026, 5, 8, 10, tzinfo=UTC)
    events = [
        _event(index, base + timedelta(minutes=index * 5), severity=EventSeverity.HIGH)
        for index in range(5)
    ]
    events.append(
        _event(
            6,
            base + timedelta(minutes=40),
            source="firewall",
            category=EventCategory.NETWORK,
            severity=EventSeverity.CRITICAL,
            title="blocked suspicious url http://malicious.example",
            ioc={"indicator": "http://malicious.example", "indicator_type": "url"},
        )
    )
    return events


async def test_anomaly_detection_returns_explainable_findings(
    ai_events: list[NormalizedEvent],
) -> None:
    service = AIAnalyticsService(InMemoryAIEventRepository(ai_events))
    filters = AIAnalyticsFilter(
        start_time=datetime(2026, 5, 8, 9, tzinfo=UTC),
        end_time=datetime(2026, 5, 8, 12, tzinfo=UTC),
    )

    response = await service.anomalies(filters, correlation_id="corr-ai")
    anomaly_types = {item.anomaly_type for item in response.items}

    assert AnomalyType.EVENT_BURST in anomaly_types
    assert AnomalyType.ENTITY_CONCENTRATION in anomaly_types
    assert AnomalyType.SUSPICIOUS_CLASSIFICATION in anomaly_types
    assert all(item.factors for item in response.items)


async def test_low_and_slow_anomaly_uses_entity_and_temporal_context() -> None:
    base = datetime(2026, 5, 8, 8, tzinfo=UTC)
    events = [
        _event(
            index,
            base + timedelta(hours=index),
            severity=EventSeverity.MEDIUM,
            title="credential access denied",
            actor="alice",
            asset="workstation-7",
        )
        for index in range(3)
    ]
    service = AIAnalyticsService(InMemoryAIEventRepository(events))
    filters = AIAnalyticsFilter(
        start_time=datetime(2026, 5, 8, 7, tzinfo=UTC),
        end_time=datetime(2026, 5, 8, 12, tzinfo=UTC),
    )

    response = await service.anomalies(filters, correlation_id=None)
    low_and_slow = [
        item for item in response.items if item.anomaly_type == AnomalyType.LOW_AND_SLOW
    ]

    assert any(item.metadata["entity"] == "alice" for item in low_and_slow)
    assert any(
        factor.name == "extended_temporal_pattern"
        for item in low_and_slow
        for factor in item.factors
    )


async def test_min_score_and_anomaly_type_filter_are_applied(
    ai_events: list[NormalizedEvent],
) -> None:
    service = AIAnalyticsService(InMemoryAIEventRepository(ai_events))
    filters = AIAnalyticsFilter(
        start_time=datetime(2026, 5, 8, 9, tzinfo=UTC),
        end_time=datetime(2026, 5, 8, 12, tzinfo=UTC),
        anomaly_type=AnomalyType.EVENT_BURST,
        min_score=50,
        limit=1,
    )

    response = await service.anomalies(filters, correlation_id=None)

    assert response.total == 1
    assert response.items[0].anomaly_type == AnomalyType.EVENT_BURST
    assert response.items[0].score >= 50


async def test_enrichment_extracts_keywords_and_classifications(
    ai_events: list[NormalizedEvent],
) -> None:
    service = AIAnalyticsService(InMemoryAIEventRepository(ai_events))
    filters = AIAnalyticsFilter(
        start_time=datetime(2026, 5, 8, 9, tzinfo=UTC),
        end_time=datetime(2026, 5, 8, 12, tzinfo=UTC),
        classification=ClassificationLabel.SUSPICIOUS_URL,
    )

    response = await service.enrichments(filters)

    assert response.total == 1
    assert ClassificationLabel.SUSPICIOUS_URL in response.items[0].classifications
    factor_names = {factor.name for factor in response.items[0].factors}
    assert "ioc_severity_context" in factor_names


def test_keyword_extraction_is_deterministic(ai_events: list[NormalizedEvent]) -> None:
    first = extract_keywords(ai_events[0])
    second = extract_keywords(ai_events[0])

    assert first == second
    assert "powershell" in first


async def test_summary_counts_ai_outputs(ai_events: list[NormalizedEvent]) -> None:
    service = AIAnalyticsService(InMemoryAIEventRepository(ai_events))
    filters = AIAnalyticsFilter(
        start_time=datetime(2026, 5, 8, 9, tzinfo=UTC),
        end_time=datetime(2026, 5, 8, 12, tzinfo=UTC),
    )

    summary = await service.summary(filters)

    assert summary.total_anomalies >= 2
    assert summary.suspicious_classifications >= 1
    assert summary.enriched_events == len(ai_events)
