"""Analytics repositories over normalized security events."""

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import case, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.sql.elements import ColumnElement

from app.analytics.schemas import (
    AnalyticsFilter,
    CountSummary,
    SourceMetric,
    TrendBucket,
    TrendPoint,
)
from app.events.models import NormalizedSecurityEvent
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


class PostgresAnalyticsRepository:
    """PostgreSQL-backed analytics repository over normalized event records."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def total_events(self, filters: AnalyticsFilter) -> int:
        statement = select(func.count()).select_from(NormalizedSecurityEvent).where(
            *_filter_clauses(filters)
        )
        async with self.session_factory() as session:
            return int(await session.scalar(statement) or 0)

    async def severity_distribution(self, filters: AnalyticsFilter) -> list[CountSummary]:
        counts = await self._count_by(NormalizedSecurityEvent.severity, filters)
        total = sum(counts.values())
        return _to_distribution(counts, total, [severity.value for severity in EventSeverity])

    async def category_distribution(self, filters: AnalyticsFilter) -> list[CountSummary]:
        counts = await self._count_by(NormalizedSecurityEvent.category, filters)
        total = sum(counts.values())
        return _to_distribution(counts, total, [category.value for category in EventCategory])

    async def trend(self, filters: AnalyticsFilter) -> list[TrendPoint]:
        return await self._trend(filters)

    async def authentication_failures(self, filters: AnalyticsFilter) -> list[TrendPoint]:
        return await self._trend(
            filters,
            extra_clauses=(
                NormalizedSecurityEvent.category == EventCategory.AUTHENTICATION.value,
                _failure_title_clause(),
            ),
        )

    async def source_metrics(self, filters: AnalyticsFilter) -> list[SourceMetric]:
        high_or_critical = func.sum(
            case(
                (
                    NormalizedSecurityEvent.severity.in_(
                        [EventSeverity.HIGH.value, EventSeverity.CRITICAL.value]
                    ),
                    1,
                ),
                else_=0,
            )
        )
        statement = (
            select(
                NormalizedSecurityEvent.source_name,
                func.count().label("total_events"),
                high_or_critical.label("high_or_critical_events"),
                func.max(NormalizedSecurityEvent.event_time).label("last_event_time"),
            )
            .where(*_filter_clauses(filters))
            .group_by(NormalizedSecurityEvent.source_name)
            .order_by(desc("total_events"), desc(NormalizedSecurityEvent.source_name))
            .limit(filters.limit)
            .offset(filters.offset)
        )
        async with self.session_factory() as session:
            rows = (await session.execute(statement)).all()
        return [
            SourceMetric(
                source=row.source_name,
                total_events=row.total_events,
                high_or_critical_events=row.high_or_critical_events or 0,
                last_event_time=row.last_event_time,
            )
            for row in rows
        ]

    async def _count_by(
        self,
        column: Any,
        filters: AnalyticsFilter,
    ) -> Counter[str]:
        statement = (
            select(column, func.count())
            .select_from(NormalizedSecurityEvent)
            .where(*_filter_clauses(filters))
            .group_by(column)
        )
        async with self.session_factory() as session:
            rows = (await session.execute(statement)).all()
        return Counter({str(name): int(count) for name, count in rows})

    async def _trend(
        self,
        filters: AnalyticsFilter,
        extra_clauses: tuple[ColumnElement[bool], ...] = (),
    ) -> list[TrendPoint]:
        bucket_start = func.date_trunc(filters.bucket.value, NormalizedSecurityEvent.event_time)
        statement = (
            select(bucket_start.label("bucket_start"), func.count().label("count"))
            .select_from(NormalizedSecurityEvent)
            .where(*_filter_clauses(filters), *extra_clauses)
            .group_by(bucket_start)
            .order_by(bucket_start)
        )
        async with self.session_factory() as session:
            rows = (await session.execute(statement)).all()
        return [
            TrendPoint(bucket_start=row.bucket_start, count=row.count)
            for row in rows
        ]


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


def _filter_clauses(filters: AnalyticsFilter) -> tuple[ColumnElement[bool], ...]:
    clauses: list[ColumnElement[bool]] = [
        NormalizedSecurityEvent.event_time >= filters.start_time,
        NormalizedSecurityEvent.event_time <= filters.end_time,
    ]
    if filters.tenant_id is not None:
        clauses.append(NormalizedSecurityEvent.tenant_id == filters.tenant_id)
    if filters.source is not None:
        clauses.append(NormalizedSecurityEvent.source_name == filters.source)
    if filters.category is not None:
        clauses.append(NormalizedSecurityEvent.category == filters.category.value)
    if filters.severity is not None:
        clauses.append(NormalizedSecurityEvent.severity == filters.severity.value)
    return tuple(clauses)


def _failure_title_clause() -> ColumnElement[bool]:
    return or_(
        NormalizedSecurityEvent.title.ilike("%fail%"),
        NormalizedSecurityEvent.title.ilike("%denied%"),
        NormalizedSecurityEvent.title.ilike("%invalid%"),
        NormalizedSecurityEvent.title.ilike("%locked%"),
    )
