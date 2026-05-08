"""IOC repository contracts and in-memory implementation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import Select, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.enrichment.models import EventIOCMatchRecord, IOCIndicatorRecord
from app.enrichment.schemas import EventIOCMatch, IOCCreateRequest, IOCListFilters, IOCRecord


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


@dataclass
class InMemoryIOCRepository(IOCRepository):
    """Local/test IOC repository."""

    iocs: list[IOCRecord] = field(default_factory=list)

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
        return None


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
    return {
        "id": uuid4(),
        "event_id": match.event_id,
        "ioc_id": match.ioc_id,
        "status": match.status.value,
        "confidence": match.confidence,
        "matched_fields": match.matched_fields,
        "confidence_factors": [factor.model_dump() for factor in match.confidence_factors],
        "metadata": match.metadata,
        "created_at": datetime.now(UTC),
    }
