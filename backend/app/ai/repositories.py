"""AI analytics repository boundaries."""

from dataclasses import dataclass
from typing import Protocol

from app.ai.schemas import AIAnalyticsFilter
from app.events.repositories import EventRepository, NormalizedEventQuery
from app.events.schemas import NormalizedEvent


class AIEventRepository(Protocol):
    """Normalized event source for deterministic AI analytics."""

    async def list_events(self, filters: AIAnalyticsFilter) -> list[NormalizedEvent]:
        """Return events in the requested scoring window."""


@dataclass
class InMemoryAIEventRepository:
    """In-memory event repository used by API tests and local app-state wiring."""

    events: list[NormalizedEvent]

    async def list_events(self, filters: AIAnalyticsFilter) -> list[NormalizedEvent]:
        return [
            event
            for event in self.events
            if filters.start_time <= event.event_time <= filters.end_time
            and (filters.tenant_id is None or event.tenant_id == filters.tenant_id)
            and (filters.category is None or event.category == filters.category)
        ]


@dataclass
class RepositoryBackedAIEventRepository:
    """Adapter that keeps AI analytics windows repository-backed."""

    repository: EventRepository

    async def list_events(self, filters: AIAnalyticsFilter) -> list[NormalizedEvent]:
        return await self.repository.list_normalized_events(
            NormalizedEventQuery(
                start_time=filters.start_time,
                end_time=filters.end_time,
                tenant_id=filters.tenant_id,
                category=filters.category,
                limit=2_000,
                newest_first=False,
            )
        )
