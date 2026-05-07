"""SOC analytics aggregation service."""

import logging
from time import perf_counter

from app.analytics.metrics import analytics_query_duration_seconds
from app.analytics.repositories import AnalyticsRepository
from app.analytics.schemas import AnalyticsFilter, OperationalKpis, SocOverview
from app.events.taxonomy import EventCategory, EventSeverity

logger = logging.getLogger(__name__)


class SocAnalyticsService:
    """Coordinate SOC metric and KPI aggregations."""

    def __init__(self, repository: AnalyticsRepository) -> None:
        self.repository = repository

    async def overview(
        self,
        filters: AnalyticsFilter,
        *,
        correlation_id: str | None,
    ) -> SocOverview:
        """Build an operational overview for SOC dashboards."""
        started = perf_counter()
        total_events = await self.repository.total_events(filters)
        severity = await self.repository.severity_distribution(filters)
        categories = await self.repository.category_distribution(filters)
        trend = await self.repository.trend(filters)
        auth_failures = await self.repository.authentication_failures(filters)
        sources = await self.repository.source_metrics(filters)
        kpis = await self.kpis(filters)
        elapsed = perf_counter() - started
        analytics_query_duration_seconds.labels(operation="overview").observe(elapsed)
        logger.info(
            "SOC analytics overview calculated",
            extra={
                "correlation_id": correlation_id,
                "total_events": total_events,
                "elapsed_ms": round(elapsed * 1000, 2),
            },
        )
        return SocOverview(
            total_events=total_events,
            severity_distribution=severity,
            category_distribution=categories,
            ingestion_trend=trend,
            authentication_failures=auth_failures,
            top_sources=sources,
            kpis=kpis,
        )

    async def kpis(self, filters: AnalyticsFilter) -> OperationalKpis:
        """Calculate pragmatic SOC KPIs from currently available event data."""
        total = await self.repository.total_events(filters)
        severities = await self.repository.severity_distribution(filters)
        categories = await self.repository.category_distribution(filters)
        sources = await self.repository.source_metrics(
            filters.model_copy(update={"limit": 100, "offset": 0})
        )
        high_count = sum(
            item.count
            for item in severities
            if item.name in {EventSeverity.HIGH.value, EventSeverity.CRITICAL.value}
        )
        auth_count = next(
            (item.count for item in categories if item.name == EventCategory.AUTHENTICATION.value),
            0,
        )
        auth_failure_trend = await self.repository.authentication_failures(filters)
        auth_failures = sum(point.count for point in auth_failure_trend)
        return OperationalKpis(
            high_severity_ratio=round(high_count / total, 4) if total else 0.0,
            authentication_failure_ratio=(
                round(auth_failures / auth_count, 4) if auth_count else 0.0
            ),
            events_per_source=round(total / len(sources), 2) if sources else 0.0,
        )
