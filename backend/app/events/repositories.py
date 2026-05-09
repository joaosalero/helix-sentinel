"""Event persistence repository contracts and local implementation."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import String, cast, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.events.models import NormalizedSecurityEvent, RawSecurityEvent
from app.events.schemas import EventIngestRequest, NormalizedEvent
from app.events.taxonomy import EventCategory, EventSeverity


@dataclass(frozen=True)
class NormalizedEventQuery:
    """Bounded query parameters for normalized event readers."""

    start_time: datetime | None = None
    end_time: datetime | None = None
    tenant_id: str | None = None
    source: str | None = None
    source_product: str | None = None
    source_vendor: str | None = None
    category: EventCategory | None = None
    severity: EventSeverity | None = None
    title: str | None = None
    actor_username: str | None = None
    actor_email: str | None = None
    actor_ip: str | None = None
    asset_hostname: str | None = None
    asset_ip: str | None = None
    ioc_value: str | None = None
    limit: int | None = None
    offset: int = 0
    newest_first: bool = False


@dataclass(frozen=True)
class RawEventRecord:
    """Raw event record retained for traceability and re-normalization."""

    id: UUID
    tenant_id: str
    source_name: str
    external_id: str | None
    payload: dict[str, object]
    received_at: datetime
    correlation_id: str
    schema_version: str = "v1"


class EventRepository:
    """Persistence boundary for raw and normalized event records."""

    async def store_raw(
        self,
        request: EventIngestRequest,
        *,
        correlation_id: str,
    ) -> RawEventRecord:
        """Persist the raw event payload."""
        raise NotImplementedError

    async def store_normalized(self, event: NormalizedEvent) -> None:
        """Persist a normalized event."""
        raise NotImplementedError

    async def list_normalized_events(
        self,
        query: NormalizedEventQuery | None = None,
    ) -> list[NormalizedEvent]:
        """Return normalized events for analytics and enrichment readers."""
        raise NotImplementedError


@dataclass
class InMemoryEventRepository(EventRepository):
    """Test/local repository that preserves ingestion behavior without a database."""

    raw_events: list[RawEventRecord] = field(default_factory=list)
    normalized_events: list[NormalizedEvent] = field(default_factory=list)

    async def store_raw(
        self,
        request: EventIngestRequest,
        *,
        correlation_id: str,
    ) -> RawEventRecord:
        record = _raw_record_from_request(request, correlation_id=correlation_id)
        self.raw_events.append(record)
        return record

    async def store_normalized(self, event: NormalizedEvent) -> None:
        self.normalized_events.append(event)

    async def list_normalized_events(
        self,
        query: NormalizedEventQuery | None = None,
    ) -> list[NormalizedEvent]:
        events = list(self.normalized_events)
        if query is None:
            return events
        filtered = [
            event
            for event in events
            if (query.start_time is None or event.event_time >= query.start_time)
            and (query.end_time is None or event.event_time <= query.end_time)
            and (query.tenant_id is None or event.tenant_id == query.tenant_id)
            and (query.source is None or event.source_name == query.source)
            and (query.source_product is None or event.source_product == query.source_product)
            and (query.source_vendor is None or event.source_vendor == query.source_vendor)
            and (query.category is None or event.category == query.category)
            and (query.severity is None or event.severity == query.severity)
            and _matches_text(event.title, query.title)
            and _matches_text(event.actor.username, query.actor_username, exact=True)
            and _matches_text(event.actor.email, query.actor_email, exact=True)
            and _matches_text(event.actor.ip_address, query.actor_ip, exact=True)
            and _matches_text(event.asset.hostname, query.asset_hostname, exact=True)
            and _matches_text(event.asset.ip_address, query.asset_ip, exact=True)
            and _event_contains_ioc(event, query.ioc_value)
        ]
        filtered.sort(key=lambda event: event.event_time, reverse=query.newest_first)
        if query.limit is None:
            return filtered[query.offset :]
        return filtered[query.offset : query.offset + query.limit]


class PostgresEventRepository(EventRepository):
    """PostgreSQL-backed raw and normalized event repository."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def store_raw(
        self,
        request: EventIngestRequest,
        *,
        correlation_id: str,
    ) -> RawEventRecord:
        record = _raw_record_from_request(request, correlation_id=correlation_id)
        async with self.session_factory() as session, session.begin():
            session.add(_to_raw_model(record))
        return record

    async def store_normalized(self, event: NormalizedEvent) -> None:
        async with self.session_factory() as session, session.begin():
            session.add(_to_normalized_model(event))

    async def list_normalized_events(
        self,
        query: NormalizedEventQuery | None = None,
    ) -> list[NormalizedEvent]:
        async with self.session_factory() as session:
            statement = select(NormalizedSecurityEvent)
            if query is not None:
                statement = _apply_normalized_query(statement, query)
            order_by = (
                NormalizedSecurityEvent.event_time.desc()
                if query is not None and query.newest_first
                else NormalizedSecurityEvent.event_time
            )
            records = await session.scalars(
                statement.order_by(order_by)
            )
            return [_to_normalized_schema(record) for record in records.all()]


def _raw_record_from_request(
    request: EventIngestRequest,
    *,
    correlation_id: str,
) -> RawEventRecord:
    return RawEventRecord(
        id=uuid4(),
        tenant_id=request.tenant_id,
        source_name=request.source.name,
        external_id=request.external_id,
        payload=dict(request.payload),
        received_at=datetime.now(UTC),
        correlation_id=correlation_id,
    )


def _to_raw_model(record: RawEventRecord) -> RawSecurityEvent:
    return RawSecurityEvent(
        id=record.id,
        tenant_id=record.tenant_id,
        source_name=record.source_name,
        external_id=record.external_id,
        payload=record.payload,
        received_at=record.received_at,
        correlation_id=record.correlation_id,
        schema_version=record.schema_version,
    )


def _to_normalized_model(event: NormalizedEvent) -> NormalizedSecurityEvent:
    return NormalizedSecurityEvent(
        id=event.id,
        raw_event_id=event.raw_event_id,
        tenant_id=event.tenant_id,
        source_name=event.source_name,
        source_product=event.source_product,
        source_vendor=event.source_vendor,
        category=event.category.value,
        severity=event.severity.value,
        title=event.title,
        actor=event.actor.model_dump(exclude_none=True),
        asset=event.asset.model_dump(exclude_none=True),
        network=event.network,
        ioc=event.ioc,
        enrichment=event.enrichment,
        event_time=event.event_time,
        ingested_at=event.ingested_at,
        normalization_version=event.normalization_version,
    )


def _to_normalized_schema(record: NormalizedSecurityEvent) -> NormalizedEvent:
    return NormalizedEvent.model_validate(
        {
            "id": record.id,
            "raw_event_id": record.raw_event_id,
            "tenant_id": record.tenant_id,
            "source_name": record.source_name,
            "source_product": record.source_product,
            "source_vendor": record.source_vendor,
            "category": record.category,
            "severity": record.severity,
            "event_time": record.event_time,
            "ingested_at": record.ingested_at,
            "title": record.title,
            "actor": _json_object(record.actor),
            "asset": _json_object(record.asset),
            "network": _json_object(record.network),
            "ioc": _json_object(record.ioc),
            "enrichment": _json_object(record.enrichment),
            "normalization_version": record.normalization_version,
        }
    )


def _json_object(value: dict[str, Any] | None) -> dict[str, Any]:
    return value or {}


def _apply_normalized_query(
    statement: Any,
    query: NormalizedEventQuery,
) -> Any:
    if query.start_time is not None:
        statement = statement.where(NormalizedSecurityEvent.event_time >= query.start_time)
    if query.end_time is not None:
        statement = statement.where(NormalizedSecurityEvent.event_time <= query.end_time)
    if query.tenant_id is not None:
        statement = statement.where(NormalizedSecurityEvent.tenant_id == query.tenant_id)
    if query.source is not None:
        statement = statement.where(NormalizedSecurityEvent.source_name == query.source)
    if query.source_product is not None:
        statement = statement.where(NormalizedSecurityEvent.source_product == query.source_product)
    if query.source_vendor is not None:
        statement = statement.where(NormalizedSecurityEvent.source_vendor == query.source_vendor)
    if query.category is not None:
        statement = statement.where(NormalizedSecurityEvent.category == query.category.value)
    if query.severity is not None:
        statement = statement.where(NormalizedSecurityEvent.severity == query.severity.value)
    if query.title is not None:
        statement = statement.where(
            NormalizedSecurityEvent.title.ilike(f"%{_escape_like(query.title)}%", escape="\\")
        )
    if query.actor_username is not None:
        statement = statement.where(
            NormalizedSecurityEvent.actor.contains({"username": query.actor_username})
        )
    if query.actor_email is not None:
        statement = statement.where(
            NormalizedSecurityEvent.actor.contains({"email": query.actor_email})
        )
    if query.actor_ip is not None:
        statement = statement.where(
            NormalizedSecurityEvent.actor.contains({"ip_address": query.actor_ip})
        )
    if query.asset_hostname is not None:
        statement = statement.where(
            NormalizedSecurityEvent.asset.contains({"hostname": query.asset_hostname})
        )
    if query.asset_ip is not None:
        statement = statement.where(
            NormalizedSecurityEvent.asset.contains({"ip_address": query.asset_ip})
        )
    if query.ioc_value is not None:
        ioc_pattern = f"%{_escape_like(query.ioc_value)}%"
        statement = statement.where(
            cast(NormalizedSecurityEvent.ioc, String).ilike(ioc_pattern, escape="\\")
        )
    if query.offset:
        statement = statement.offset(query.offset)
    if query.limit is not None:
        statement = statement.limit(query.limit)
    return statement


def _matches_text(value: str | None, expected: str | None, *, exact: bool = False) -> bool:
    if expected is None:
        return True
    if value is None:
        return False
    if exact:
        return value.lower() == expected.lower()
    return expected.lower() in value.lower()


def _event_contains_ioc(event: NormalizedEvent, expected: str | None) -> bool:
    if expected is None:
        return True
    needle = expected.lower()
    return any(needle in str(value).lower() for value in event.ioc.values())


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
