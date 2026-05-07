"""SOC analytics aggregation service tests."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.analytics.repositories import InMemoryAnalyticsRepository
from app.analytics.schemas import AnalyticsFilter, TrendBucket
from app.analytics.service import SocAnalyticsService
from app.events.schemas import NormalizedEvent
from app.events.taxonomy import EventCategory, EventSeverity


def _event(
    *,
    category: EventCategory,
    severity: EventSeverity,
    source: str,
    event_time: datetime,
    title: str = "event",
    tenant_id: str = "tenant-a",
) -> NormalizedEvent:
    return NormalizedEvent(
        id=uuid4(),
        raw_event_id=uuid4(),
        tenant_id=tenant_id,
        source_name=source,
        source_product=None,
        source_vendor=None,
        category=category,
        severity=severity,
        event_time=event_time,
        ingested_at=event_time,
        title=title,
    )


@pytest.fixture
def analytics_events() -> list[NormalizedEvent]:
    base = datetime(2026, 5, 7, tzinfo=UTC)
    return [
        _event(
            category=EventCategory.AUTHENTICATION,
            severity=EventSeverity.HIGH,
            source="okta",
            event_time=base,
            title="login failed",
        ),
        _event(
            category=EventCategory.AUTHENTICATION,
            severity=EventSeverity.INFO,
            source="okta",
            event_time=base + timedelta(hours=2),
            title="login succeeded",
        ),
        _event(
            category=EventCategory.ENDPOINT,
            severity=EventSeverity.CRITICAL,
            source="edr",
            event_time=base + timedelta(days=1),
        ),
        _event(
            category=EventCategory.NETWORK,
            severity=EventSeverity.MEDIUM,
            source="firewall",
            event_time=base + timedelta(days=1, hours=2),
            tenant_id="tenant-b",
        ),
    ]


async def test_overview_calculates_core_soc_metrics(
    analytics_events: list[NormalizedEvent],
) -> None:
    service = SocAnalyticsService(InMemoryAnalyticsRepository(analytics_events))
    filters = AnalyticsFilter(
        start_time=datetime(2026, 5, 6, tzinfo=UTC),
        end_time=datetime(2026, 5, 10, tzinfo=UTC),
    )

    overview = await service.overview(filters, correlation_id="corr-analytics")

    assert overview.total_events == 4
    critical = next(item for item in overview.severity_distribution if item.name == "critical")
    authentication = next(
        item for item in overview.category_distribution if item.name == "authentication"
    )
    assert critical.count == 1
    assert authentication.count == 2
    assert sum(point.count for point in overview.authentication_failures) == 1
    assert overview.kpis.high_severity_ratio == 0.5
    assert overview.kpis.authentication_failure_ratio == 0.5


async def test_filters_apply_tenant_source_category_and_severity(
    analytics_events: list[NormalizedEvent],
) -> None:
    repository = InMemoryAnalyticsRepository(analytics_events)
    filters = AnalyticsFilter(
        start_time=datetime(2026, 5, 6, tzinfo=UTC),
        end_time=datetime(2026, 5, 10, tzinfo=UTC),
        tenant_id="tenant-a",
        source="okta",
        category=EventCategory.AUTHENTICATION,
        severity=EventSeverity.HIGH,
    )

    assert await repository.total_events(filters) == 1


async def test_hourly_trend_buckets_events(analytics_events: list[NormalizedEvent]) -> None:
    repository = InMemoryAnalyticsRepository(analytics_events)
    filters = AnalyticsFilter(
        start_time=datetime(2026, 5, 7, tzinfo=UTC),
        end_time=datetime(2026, 5, 7, 23, 59, tzinfo=UTC),
        bucket=TrendBucket.HOUR,
    )

    trend = await repository.trend(filters)

    assert [point.count for point in trend] == [1, 1]


async def test_source_metrics_are_paginated(analytics_events: list[NormalizedEvent]) -> None:
    repository = InMemoryAnalyticsRepository(analytics_events)
    filters = AnalyticsFilter(
        start_time=datetime(2026, 5, 6, tzinfo=UTC),
        end_time=datetime(2026, 5, 10, tzinfo=UTC),
        limit=1,
        offset=0,
    )

    sources = await repository.source_metrics(filters)

    assert len(sources) == 1
    assert sources[0].source == "okta"
    assert sources[0].total_events == 2
