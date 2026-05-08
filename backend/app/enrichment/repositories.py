"""IOC repository contracts and in-memory implementation."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import Select, desc, distinct, func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.sql.elements import ColumnElement

from app.enrichment.models import EventIOCMatchRecord, IOCIndicatorRecord
from app.enrichment.schemas import (
    EventIOCMatch,
    IOCCreateRequest,
    IOCListFilters,
    IOCMatchActivitySummary,
    IOCMatchAnalyticsFilter,
    IOCMatchMetric,
    IOCMatchTrendPoint,
    IOCRecord,
    TopIOCMatch,
)
from app.enrichment.taxonomy import IOCSeverity


class IOCRepository:
    """Persistence boundary for IOC management."""

    async def create(self, request: IOCCreateRequest) -> IOCRecord:
        """Persist an IOC."""
        raise NotImplementedError

    async def get(self, ioc_id: UUID) -> IOCRecord | None:
        """Return an IOC by ID."""
        raise NotImplementedError

    async def list_iocs(self, filters: IOCListFilters) -> tuple[list[IOCRecord], int]:
        """Return filtered and paginated IOCs."""
        raise NotImplementedError

    async def all_active(self) -> list[IOCRecord]:
        """Return active IOCs for deterministic enrichment."""
        raise NotImplementedError

    async def all_iocs(self) -> list[IOCRecord]:
        """Return all IOCs for inventory summaries."""
        raise NotImplementedError

    async def store_matches(self, matches: list[EventIOCMatch]) -> None:
        """Persist event-to-IOC enrichment matches."""
        raise NotImplementedError

    async def match_activity(
        self,
        filters: IOCMatchAnalyticsFilter,
    ) -> IOCMatchActivitySummary:
        """Return tenant-aware IOC match analytics."""
        raise NotImplementedError


@dataclass
class InMemoryIOCRepository(IOCRepository):
    """Local/test IOC repository."""

    iocs: list[IOCRecord] = field(default_factory=list)
    matches: list[EventIOCMatch] = field(default_factory=list)

    async def create(self, request: IOCCreateRequest) -> IOCRecord:
        now = datetime.now(UTC)
        record = IOCRecord(
            id=uuid4(),
            indicator_type=request.indicator_type,
            value=request.value,
            confidence=request.confidence,
            severity=request.severity,
            source_name=request.source_name,
            source_reliability=request.source_reliability,
            first_seen=request.first_seen,
            last_seen=request.last_seen,
            expires_at=request.expires_at,
            tags=request.tags,
            notes=request.notes,
            metadata=request.metadata,
            created_at=now,
            updated_at=now,
        )
        self.iocs.append(record)
        return record

    async def get(self, ioc_id: UUID) -> IOCRecord | None:
        return next((ioc for ioc in self.iocs if ioc.id == ioc_id), None)

    async def list_iocs(self, filters: IOCListFilters) -> tuple[list[IOCRecord], int]:
        now = datetime.now(UTC)
        filtered = [
            ioc
            for ioc in self.iocs
            if (filters.indicator_type is None or ioc.indicator_type == filters.indicator_type)
            and (filters.severity is None or ioc.severity == filters.severity)
            and (filters.source_name is None or ioc.source_name == filters.source_name)
            and (filters.tag is None or filters.tag in ioc.tags)
            and ioc.confidence >= filters.min_confidence
            and (not filters.active_only or ioc.expires_at is None or ioc.expires_at > now)
        ]
        filtered.sort(key=lambda ioc: (ioc.confidence, ioc.last_seen), reverse=True)
        return filtered[filters.offset : filters.offset + filters.limit], len(filtered)

    async def all_active(self) -> list[IOCRecord]:
        now = datetime.now(UTC)
        return [ioc for ioc in self.iocs if ioc.expires_at is None or ioc.expires_at > now]

    async def all_iocs(self) -> list[IOCRecord]:
        return list(self.iocs)

    async def store_matches(self, matches: list[EventIOCMatch]) -> None:
        existing = {(match.event_id, match.ioc_id) for match in self.matches}
        matched_at = datetime.now(UTC)
        for match in matches:
            key = (match.event_id, match.ioc_id)
            if key in existing:
                continue
            self.matches.append(
                match.model_copy(update={"metadata": {**match.metadata, "matched_at": matched_at}})
            )
            existing.add(key)

    async def match_activity(
        self,
        filters: IOCMatchAnalyticsFilter,
    ) -> IOCMatchActivitySummary:
        iocs_by_id = {ioc.id: ioc for ioc in self.iocs}
        matches = [
            match
            for match in self.matches
            if _match_in_window(match, filters)
            and (filters.tenant_id is None or match.metadata.get("tenant_id") == filters.tenant_id)
            and (
                filters.indicator_type is None
                or match.indicator_type == filters.indicator_type
            )
            and match.confidence >= filters.min_confidence
        ]
        indicator_counts = Counter(match.indicator_type.value for match in matches)
        severity_counts = Counter(
            iocs_by_id[match.ioc_id].severity.value
            for match in matches
            if match.ioc_id in iocs_by_id
        )
        return IOCMatchActivitySummary(
            total_matches=len(matches),
            matched_events=len({match.event_id for match in matches}),
            high_confidence_matches=sum(match.confidence >= 70 for match in matches),
            active_iocs=len(await self.all_active()),
            by_indicator_type=_metric_list(indicator_counts),
            by_severity=_metric_list(severity_counts, [severity.value for severity in IOCSeverity]),
            trend=_match_trend(matches),
            top_iocs=_top_ioc_matches(matches, iocs_by_id, filters),
        )


class PostgresIOCRepository(IOCRepository):
    """PostgreSQL-backed IOC inventory and enrichment match repository."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def create(self, request: IOCCreateRequest) -> IOCRecord:
        now = datetime.now(UTC)
        record = _ioc_record_from_request(request, now=now)
        async with self.session_factory() as session, session.begin():
            session.add(_to_ioc_model(record))
        return record

    async def get(self, ioc_id: UUID) -> IOCRecord | None:
        async with self.session_factory() as session:
            model = await session.get(IOCIndicatorRecord, ioc_id)
            return _to_ioc_record(model) if model is not None else None

    async def list_iocs(self, filters: IOCListFilters) -> tuple[list[IOCRecord], int]:
        async with self.session_factory() as session:
            statement = _filtered_ioc_statement(filters).order_by(
                IOCIndicatorRecord.confidence.desc(),
                IOCIndicatorRecord.last_seen.desc(),
            )
            models = list((await session.scalars(statement)).all())
            total = len(models)
            window = models[filters.offset : filters.offset + filters.limit]
            return [_to_ioc_record(model) for model in window], total

    async def all_active(self) -> list[IOCRecord]:
        now = datetime.now(UTC)
        async with self.session_factory() as session:
            models = await session.scalars(
                select(IOCIndicatorRecord).where(
                    or_(
                        IOCIndicatorRecord.expires_at.is_(None),
                        IOCIndicatorRecord.expires_at > now,
                    )
                )
            )
            return [_to_ioc_record(model) for model in models.all()]

    async def all_iocs(self) -> list[IOCRecord]:
        async with self.session_factory() as session:
            models = await session.scalars(select(IOCIndicatorRecord))
            return [_to_ioc_record(model) for model in models.all()]

    async def store_matches(self, matches: list[EventIOCMatch]) -> None:
        if not matches:
            return
        values = [_to_match_values(match) for match in matches]
        statement = insert(EventIOCMatchRecord).values(values)
        statement = statement.on_conflict_do_nothing(
            index_elements=[EventIOCMatchRecord.event_id, EventIOCMatchRecord.ioc_id]
        )
        async with self.session_factory() as session, session.begin():
            await session.execute(statement)

    async def match_activity(
        self,
        filters: IOCMatchAnalyticsFilter,
    ) -> IOCMatchActivitySummary:
        clauses = _match_filter_clauses(filters)
        active_count = len(await self.all_active())
        async with self.session_factory() as session:
            total_matches = int(
                await session.scalar(
                    select(func.count())
                    .select_from(EventIOCMatchRecord)
                    .join(IOCIndicatorRecord)
                    .where(*clauses)
                )
                or 0
            )
            matched_events = int(
                await session.scalar(
                    select(func.count(distinct(EventIOCMatchRecord.event_id)))
                    .select_from(EventIOCMatchRecord)
                    .join(IOCIndicatorRecord)
                    .where(*clauses)
                )
                or 0
            )
            high_confidence = int(
                await session.scalar(
                    select(func.count())
                    .select_from(EventIOCMatchRecord)
                    .join(IOCIndicatorRecord)
                    .where(*clauses, EventIOCMatchRecord.confidence >= 70)
                )
                or 0
            )
            indicator_rows = (
                await session.execute(
                    select(IOCIndicatorRecord.indicator_type, func.count())
                    .join(EventIOCMatchRecord)
                    .where(*clauses)
                    .group_by(IOCIndicatorRecord.indicator_type)
                )
            ).all()
            severity_rows = (
                await session.execute(
                    select(IOCIndicatorRecord.severity, func.count())
                    .join(EventIOCMatchRecord)
                    .where(*clauses)
                    .group_by(IOCIndicatorRecord.severity)
                )
            ).all()
            trend_bucket = func.date_trunc("day", EventIOCMatchRecord.created_at)
            trend_rows = (
                await session.execute(
                    select(trend_bucket.label("bucket_start"), func.count().label("count"))
                    .select_from(EventIOCMatchRecord)
                    .join(IOCIndicatorRecord)
                    .where(*clauses)
                    .group_by(trend_bucket)
                    .order_by(trend_bucket)
                )
            ).all()
            top_rows = (
                await session.execute(
                    select(
                        IOCIndicatorRecord.id,
                        IOCIndicatorRecord.indicator_type,
                        IOCIndicatorRecord.value,
                        IOCIndicatorRecord.severity,
                        IOCIndicatorRecord.source_name,
                        func.count().label("match_count"),
                        func.max(EventIOCMatchRecord.confidence).label("max_confidence"),
                        func.max(EventIOCMatchRecord.created_at).label("last_matched_at"),
                    )
                    .join(EventIOCMatchRecord)
                    .where(*clauses)
                    .group_by(
                        IOCIndicatorRecord.id,
                        IOCIndicatorRecord.indicator_type,
                        IOCIndicatorRecord.value,
                        IOCIndicatorRecord.severity,
                        IOCIndicatorRecord.source_name,
                    )
                    .order_by(desc("match_count"), desc("last_matched_at"))
                    .limit(filters.limit)
                    .offset(filters.offset)
                )
            ).all()
        return IOCMatchActivitySummary(
            total_matches=total_matches,
            matched_events=matched_events,
            high_confidence_matches=high_confidence,
            active_iocs=active_count,
            by_indicator_type=_metric_list(
                Counter({str(name): int(count) for name, count in indicator_rows})
            ),
            by_severity=_metric_list(
                Counter({str(name): int(count) for name, count in severity_rows}),
                [severity.value for severity in IOCSeverity],
            ),
            trend=[
                IOCMatchTrendPoint(bucket_start=row.bucket_start, count=row.count)
                for row in trend_rows
            ],
            top_iocs=[
                TopIOCMatch(
                    ioc_id=row.id,
                    indicator_type=row.indicator_type,
                    value=row.value,
                    severity=row.severity,
                    source_name=row.source_name,
                    match_count=row.match_count,
                    max_confidence=row.max_confidence,
                    last_matched_at=row.last_matched_at,
                )
                for row in top_rows
            ],
        )


def _filtered_ioc_statement(filters: IOCListFilters) -> Select[tuple[IOCIndicatorRecord]]:
    statement = select(IOCIndicatorRecord)
    now = datetime.now(UTC)
    if filters.indicator_type is not None:
        statement = statement.where(
            IOCIndicatorRecord.indicator_type == filters.indicator_type.value
        )
    if filters.severity is not None:
        statement = statement.where(IOCIndicatorRecord.severity == filters.severity.value)
    if filters.source_name is not None:
        statement = statement.where(IOCIndicatorRecord.source_name == filters.source_name)
    if filters.tag is not None:
        statement = statement.where(IOCIndicatorRecord.tags.contains([filters.tag]))
    if filters.min_confidence:
        statement = statement.where(IOCIndicatorRecord.confidence >= filters.min_confidence)
    if filters.active_only:
        statement = statement.where(
            or_(IOCIndicatorRecord.expires_at.is_(None), IOCIndicatorRecord.expires_at > now)
        )
    return statement


def _match_filter_clauses(
    filters: IOCMatchAnalyticsFilter,
) -> tuple[ColumnElement[bool], ...]:
    clauses: list[ColumnElement[bool]] = [
        EventIOCMatchRecord.created_at >= filters.start_time,
        EventIOCMatchRecord.created_at <= filters.end_time,
        EventIOCMatchRecord.confidence >= filters.min_confidence,
    ]
    if filters.tenant_id is not None:
        clauses.append(EventIOCMatchRecord.metadata_["tenant_id"].astext == filters.tenant_id)
    if filters.indicator_type is not None:
        clauses.append(IOCIndicatorRecord.indicator_type == filters.indicator_type.value)
    return tuple(clauses)


def _ioc_record_from_request(request: IOCCreateRequest, *, now: datetime) -> IOCRecord:
    return IOCRecord(
        id=uuid4(),
        indicator_type=request.indicator_type,
        value=request.value,
        confidence=request.confidence,
        severity=request.severity,
        source_name=request.source_name,
        source_reliability=request.source_reliability,
        first_seen=request.first_seen,
        last_seen=request.last_seen,
        expires_at=request.expires_at,
        tags=request.tags,
        notes=request.notes,
        metadata=request.metadata,
        created_at=now,
        updated_at=now,
    )


def _to_ioc_model(record: IOCRecord) -> IOCIndicatorRecord:
    return IOCIndicatorRecord(
        id=record.id,
        indicator_type=record.indicator_type.value,
        value=record.value,
        confidence=record.confidence,
        severity=record.severity.value,
        source_name=record.source_name,
        source_reliability=record.source_reliability.value,
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        expires_at=record.expires_at,
        tags=record.tags,
        notes=record.notes,
        metadata_=record.metadata,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def _to_ioc_record(model: IOCIndicatorRecord) -> IOCRecord:
    return IOCRecord.model_validate(
        {
            "id": model.id,
            "indicator_type": model.indicator_type,
            "value": model.value,
            "confidence": model.confidence,
            "severity": model.severity,
            "source_name": model.source_name,
            "source_reliability": model.source_reliability,
            "first_seen": model.first_seen,
            "last_seen": model.last_seen,
            "expires_at": model.expires_at,
            "tags": model.tags,
            "notes": model.notes,
            "metadata": model.metadata_,
            "created_at": model.created_at,
            "updated_at": model.updated_at,
        }
    )


def _to_match_values(match: EventIOCMatch) -> dict[str, object]:
    matched_at = datetime.now(UTC)
    return {
        "id": uuid4(),
        "event_id": match.event_id,
        "ioc_id": match.ioc_id,
        "status": match.status.value,
        "confidence": match.confidence,
        "matched_fields": match.matched_fields,
        "confidence_factors": [factor.model_dump() for factor in match.confidence_factors],
        "metadata": match.metadata,
        "created_at": matched_at,
    }


def _match_in_window(match: EventIOCMatch, filters: IOCMatchAnalyticsFilter) -> bool:
    matched_at = match.metadata.get("matched_at")
    if isinstance(matched_at, datetime):
        return filters.start_time <= matched_at <= filters.end_time
    return True


def _metric_list(
    counts: Counter[str],
    ordered_names: list[str] | None = None,
) -> list[IOCMatchMetric]:
    names = ordered_names or sorted(counts)
    return [IOCMatchMetric(name=name, count=counts.get(name, 0)) for name in names]


def _match_trend(matches: list[EventIOCMatch]) -> list[IOCMatchTrendPoint]:
    counts: Counter[datetime] = Counter()
    for match in matches:
        matched_at = match.metadata.get("matched_at")
        if not isinstance(matched_at, datetime):
            continue
        bucket = matched_at.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        counts[bucket] += 1
    return [
        IOCMatchTrendPoint(bucket_start=bucket, count=count)
        for bucket, count in sorted(counts.items(), key=lambda item: item[0])
    ]


def _top_ioc_matches(
    matches: list[EventIOCMatch],
    iocs_by_id: dict[UUID, IOCRecord],
    filters: IOCMatchAnalyticsFilter,
) -> list[TopIOCMatch]:
    grouped: dict[UUID, list[EventIOCMatch]] = defaultdict(list)
    for match in matches:
        if match.ioc_id in iocs_by_id:
            grouped[match.ioc_id].append(match)
    items = [
        TopIOCMatch(
            ioc_id=ioc_id,
            indicator_type=iocs_by_id[ioc_id].indicator_type,
            value=iocs_by_id[ioc_id].value,
            severity=iocs_by_id[ioc_id].severity,
            source_name=iocs_by_id[ioc_id].source_name,
            match_count=len(related),
            max_confidence=max(match.confidence for match in related),
            last_matched_at=max(
                (
                    matched_at
                    for matched_at in (match.metadata.get("matched_at") for match in related)
                    if isinstance(matched_at, datetime)
                ),
                default=datetime.now(UTC),
            ),
        )
        for ioc_id, related in grouped.items()
    ]
    items.sort(key=lambda item: (item.match_count, item.last_matched_at), reverse=True)
    return items[filters.offset : filters.offset + filters.limit]
