"""SOC analytics aggregation service tests."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.ai.schemas import AIAnalyticsSummary
from app.analytics.repositories import InMemoryAnalyticsRepository
from app.analytics.schemas import AnalyticsFilter, TrendBucket
from app.analytics.service import SocAnalyticsService
from app.detections.repositories import AlertReportingSnapshot
from app.detections.schemas import DetectionCoverageSummary
from app.events.schemas import NormalizedEvent
from app.events.taxonomy import EventCategory, EventSeverity
from app.threats.schemas import ThreatSummary


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


async def test_report_combines_event_alert_threat_and_ai_kpis(
    analytics_events: list[NormalizedEvent],
) -> None:
    service = SocAnalyticsService(InMemoryAnalyticsRepository(analytics_events))
    filters = AnalyticsFilter(
        start_time=datetime(2026, 5, 6, tzinfo=UTC),
        end_time=datetime(2026, 5, 10, tzinfo=UTC),
    )

    report = await service.report(
        filters,
        alert_snapshot=AlertReportingSnapshot(
            total_alerts=3,
            open_alerts=1,
            acknowledged_alerts=1,
            closed_alerts=1,
            high_or_critical_alerts=1,
            unassigned_open_alerts=1,
            mtta_minutes=12.5,
            mttr_minutes=90.0,
            true_positive_alerts=1,
        ),
        threat_summary=ThreatSummary(
            total_insights=2,
            high_or_critical=1,
            ioc_related=1,
            repeated_auth_failures=0,
            suspicious_ip_reuse=0,
            endpoint_repetition=1,
            event_bursts=0,
            max_risk_score=75,
        ),
        ai_summary=AIAnalyticsSummary(
            total_anomalies=2,
            high_confidence=1,
            max_score=80,
            suspicious_classifications=2,
            enriched_events=4,
        ),
        correlation_id="corr-report",
        detection_coverage=DetectionCoverageSummary(
            period_start=datetime(2026, 5, 6, tzinfo=UTC),
            period_end=datetime(2026, 5, 10, tzinfo=UTC),
            total_rules=4,
            active_rules=3,
            mapped_rules=1,
            unmapped_rules=3,
            active_mapped_rules=1,
            techniques_covered=1,
            tactics_covered=1,
            coverage_ratio=0.25,
            alerting_rules=1,
            silent_active_rules=2,
            total_alerts=3,
            top_techniques=[],
            tactic_coverage=[],
            noisy_rules=[],
            silent_rules=[],
        ),
    )

    assert report.executive_summary.posture == "elevated"
    assert report.executive_summary.risk_score > 0
    assert report.executive_kpis.alert_closure_ratio == 0.5
    assert report.executive_kpis.detection_coverage_ratio == 0.25
    assert report.alert_workflow.true_positive_rate == 1.0
    assert report.threat_summary.high_or_critical == 1
    assert report.ai_summary.high_confidence == 1
    assert {finding.name for finding in report.findings} >= {
        "open_alert_queue",
        "high_risk_threat_insights",
        "high_confidence_ai_anomalies",
        "low_detection_mapping",
        "silent_active_rules",
    }
