"""Threat Analytics service tests."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.events.schemas import NormalizedActor, NormalizedAsset, NormalizedEvent
from app.events.taxonomy import EventCategory, EventSeverity
from app.threats.repositories import InMemoryThreatEventRepository
from app.threats.schemas import ThreatAnalyticsFilter
from app.threats.service import ThreatAnalyticsService
from app.threats.taxonomy import IndicatorType, ThreatInsightType


def _event(
    *,
    category: EventCategory,
    severity: EventSeverity,
    title: str,
    event_time: datetime,
    source: str = "sensor",
    actor: NormalizedActor | None = None,
    asset: NormalizedAsset | None = None,
    ioc: dict[str, object] | None = None,
    network: dict[str, object] | None = None,
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
        actor=actor or NormalizedActor(),
        asset=asset or NormalizedAsset(),
        ioc=ioc or {},
        network=network or {},
    )


@pytest.fixture
def threat_events() -> list[NormalizedEvent]:
    base = datetime(2026, 5, 8, 10, tzinfo=UTC)
    return [
        _event(
            category=EventCategory.AUTHENTICATION,
            severity=EventSeverity.MEDIUM,
            title="login failed",
            event_time=base,
            source="okta",
            actor=NormalizedActor(email="analyst@example.com", ip_address="203.0.113.10"),
        ),
        _event(
            category=EventCategory.AUTHENTICATION,
            severity=EventSeverity.MEDIUM,
            title="login failed",
            event_time=base + timedelta(minutes=5),
            source="okta",
            actor=NormalizedActor(email="analyst@example.com", ip_address="203.0.113.10"),
        ),
        _event(
            category=EventCategory.AUTHENTICATION,
            severity=EventSeverity.HIGH,
            title="login failed",
            event_time=base + timedelta(minutes=10),
            source="okta",
            actor=NormalizedActor(email="analyst@example.com", ip_address="203.0.113.10"),
        ),
        _event(
            category=EventCategory.ENDPOINT,
            severity=EventSeverity.HIGH,
            title="suspicious process",
            event_time=base + timedelta(minutes=15),
            source="edr",
            asset=NormalizedAsset(hostname="endpoint-01"),
        ),
        _event(
            category=EventCategory.ENDPOINT,
            severity=EventSeverity.CRITICAL,
            title="suspicious process",
            event_time=base + timedelta(minutes=20),
            source="edr",
            asset=NormalizedAsset(hostname="endpoint-01"),
            ioc={"file_hash": "abc123"},
        ),
        _event(
            category=EventCategory.NETWORK,
            severity=EventSeverity.HIGH,
            title="domain match",
            event_time=base + timedelta(minutes=25),
            source="firewall",
            ioc={"indicator": "malicious.example", "indicator_type": "domain"},
        ),
    ]


async def test_generates_repeated_auth_endpoint_and_ioc_insights(
    threat_events: list[NormalizedEvent],
) -> None:
    service = ThreatAnalyticsService(InMemoryThreatEventRepository(threat_events))
    filters = ThreatAnalyticsFilter(
        start_time=datetime(2026, 5, 8, 9, tzinfo=UTC),
        end_time=datetime(2026, 5, 8, 12, tzinfo=UTC),
    )

    response = await service.insights(filters, correlation_id="corr-threat")
    insight_types = {insight.insight_type for insight in response.items}

    assert ThreatInsightType.REPEATED_AUTH_FAILURE in insight_types
    assert ThreatInsightType.ENDPOINT_REPETITION in insight_types
    assert ThreatInsightType.IOC_MATCH in insight_types
    assert response.total >= 4


async def test_ioc_filtering_matches_indicator_type_and_value(
    threat_events: list[NormalizedEvent],
) -> None:
    service = ThreatAnalyticsService(InMemoryThreatEventRepository(threat_events))
    filters = ThreatAnalyticsFilter(
        start_time=datetime(2026, 5, 8, 9, tzinfo=UTC),
        end_time=datetime(2026, 5, 8, 12, tzinfo=UTC),
        indicator_type=IndicatorType.DOMAIN,
        indicator_value="malicious.example",
    )

    response = await service.insights(filters, correlation_id=None)

    assert response.total == 1
    assert response.items[0].iocs[0].indicator_type == IndicatorType.DOMAIN


async def test_min_risk_and_pagination_are_applied(threat_events: list[NormalizedEvent]) -> None:
    service = ThreatAnalyticsService(InMemoryThreatEventRepository(threat_events))
    filters = ThreatAnalyticsFilter(
        start_time=datetime(2026, 5, 8, 9, tzinfo=UTC),
        end_time=datetime(2026, 5, 8, 12, tzinfo=UTC),
        min_risk_score=60,
        limit=1,
        offset=0,
    )

    response = await service.insights(filters, correlation_id=None)

    assert response.total >= 1
    assert len(response.items) == 1
    assert response.items[0].risk_score >= 60


async def test_summary_counts_generated_insights(threat_events: list[NormalizedEvent]) -> None:
    service = ThreatAnalyticsService(InMemoryThreatEventRepository(threat_events))
    filters = ThreatAnalyticsFilter(
        start_time=datetime(2026, 5, 8, 9, tzinfo=UTC),
        end_time=datetime(2026, 5, 8, 12, tzinfo=UTC),
    )

    summary = await service.summary(filters)

    assert summary.total_insights >= 4
    assert summary.ioc_related == 2
    assert summary.repeated_auth_failures == 1
    assert summary.endpoint_repetition == 1
    assert summary.max_risk_score > 0


async def test_temporal_filter_limits_events(threat_events: list[NormalizedEvent]) -> None:
    service = ThreatAnalyticsService(InMemoryThreatEventRepository(threat_events))
    filters = ThreatAnalyticsFilter(
        start_time=datetime(2026, 5, 8, 10, 20, tzinfo=UTC),
        end_time=datetime(2026, 5, 8, 10, 30, tzinfo=UTC),
    )

    response = await service.insights(filters, correlation_id=None)

    assert response.total == 2
    assert all(insight.temporal.first_seen >= filters.start_time for insight in response.items)

