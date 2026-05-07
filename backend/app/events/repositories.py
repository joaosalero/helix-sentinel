"""Event persistence repository contracts and local implementation."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.events.schemas import EventIngestRequest, NormalizedEvent


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
        record = RawEventRecord(
            id=uuid4(),
            tenant_id=request.tenant_id,
            source_name=request.source.name,
            external_id=request.external_id,
            payload=dict(request.payload),
            received_at=datetime.now(UTC),
            correlation_id=correlation_id,
        )
        self.raw_events.append(record)
        return record

    async def store_normalized(self, event: NormalizedEvent) -> None:
        self.normalized_events.append(event)

