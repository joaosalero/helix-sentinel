"""IOC repository contracts and in-memory implementation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.enrichment.schemas import IOCCreateRequest, IOCListFilters, IOCRecord


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
