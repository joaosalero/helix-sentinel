"""Analytics repositories over normalized security events."""

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from app.analytics.schemas import (
    AnalyticsFilter,
    CountSummary,
    SourceMetric,
    TrendBucket,
    TrendPoint,
)
from app.events.schemas import NormalizedEvent
from app.events.taxonomy import EventCategory, EventSeverity


class AnalyticsRepository(Protocol):
    """Aggregation query boundary for SOC analytics."""

    async def total_events(self, filters: AnalyticsFilter) -> int:
        """Return total events matching filters."""

    async def severity_distribution(self, filters: AnalyticsFilter) -> list[CountSummary]:
        """Return event counts by severity."""

    async def category_distribution(self, filters: AnalyticsFilter) -> list[CountSummary]:
        """Return event counts by category."""

    async def trend(self, filters: AnalyticsFilter) -> list[TrendPoint]:
        """Return event volume trend."""

    async def authentication_failures(self, filters: AnalyticsFilter) -> list[TrendPoint]:
        """Return authentication failure trend."""

    async def source_metrics(self, filters: AnalyticsFilter) -> list[SourceMetric]:
        """Return paginated event source metrics."""


@dataclass
class InMemoryAnalyticsRepository:
    """In-memory analytics repository used by local wiring and tests."""

    events: list[NormalizedEvent]

    async def total_events(self, filters: AnalyticsFilter) -> int:
        return len(_apply_filters(self.events, filters))

    async def severity_distribution(self, filters: AnalyticsFilter) -> list[CountSummary]:
        events = _apply_filters(self.events, filters)
        counts = Counter(event.severity.value for event in events)
        return _to_distribution(counts, len(events), [severity.value for severity in EventSeverity])

    async def category_distribution(self, filters: AnalyticsFilter) -> list[CountSummary]:
        events = _apply_filters(self.events, filters)
        counts = Counter(event.category.value for event in events)
        return _to_distribution(counts, len(events), [category.value for category in EventCategory])

    async def trend(self, filters: AnalyticsFilter) -> list[TrendPoint]:
        return _trend(_apply_filters(self.events, filters), filters.bucket)

    async def authentication_failures(self, filters: AnalyticsFilter) -> list[TrendPoint]:
        events = [
            event
            for event in _apply_filters(self.events, filters)
            if event.category == EventCategory.AUTHENTICATION and _looks_like_failure(event.title)
        ]
        return _trend(events, filters.bucket)

    async def source_metrics(self, filters: AnalyticsFilter) -> list[SourceMetric]:
        grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in _apply_filters(self.events, filters):
            grouped[event.source_name].append(event)

        metrics = [
            SourceMetric(
                source=source,
                total_events=len(source_events),
                high_or_critical_events=sum(
                    event.severity in {EventSeverity.HIGH, EventSeverity.CRITICAL}
                    for event in source_events
                ),
                last_event_time=max((event.event_time for event in source_events), default=None),
            )
            for source, source_events in grouped.items()
        ]
        metrics.sort(key=lambda item: (item.total_events, item.source), reverse=True)
        return metrics[filters.offset : filters.offset + filters.limit]


def _apply_filters(
    events: list[NormalizedEvent],
    filters: AnalyticsFilter,
) -> list[NormalizedEvent]:
    return [
        event
        for event in events
        if filters.start_time <= event.event_time <= filters.end_time
        and (filters.tenant_id is None or event.tenant_id == filters.tenant_id)
        and (filters.source is None or event.source_name == filters.source)
        and (filters.category is None or event.category == filters.category)
        and (filters.severity is None or event.severity == filters.severity)
    ]


def _to_distribution(
    counts: Counter[str],
    total: int,
    ordered_names: list[str],
) -> list[CountSummary]:
    return [
        CountSummary(
            name=name,
            count=counts.get(name, 0),
            percentage=round((counts.get(name, 0) / total) * 100, 2) if total else 0.0,
        )
        for name in ordered_names
    ]


def _trend(events: list[NormalizedEvent], bucket: TrendBucket) -> list[TrendPoint]:
    counts: Counter[datetime] = Counter(_bucket_start(event.event_time, bucket) for event in events)
    return [
        TrendPoint(bucket_start=bucket_start, count=count)
        for bucket_start, count in sorted(counts.items(), key=lambda item: item[0])
    ]


def _bucket_start(value: datetime, bucket: TrendBucket) -> datetime:
    normalized = value.astimezone(UTC)
    if bucket == TrendBucket.HOUR:
        return normalized.replace(minute=0, second=0, microsecond=0)
    return normalized.replace(hour=0, minute=0, second=0, microsecond=0)


def _looks_like_failure(title: str) -> bool:
    value = title.lower()
    return any(term in value for term in ("fail", "denied", "invalid", "locked"))
