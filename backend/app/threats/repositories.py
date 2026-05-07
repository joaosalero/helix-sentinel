"""Threat Analytics repository boundaries."""

from dataclasses import dataclass
from typing import Protocol

from app.events.schemas import NormalizedEvent
from app.threats.schemas import ThreatAnalyticsFilter


class ThreatEventRepository(Protocol):
    """Repository boundary for normalized events used in threat analytics."""

    async def list_events(self, filters: ThreatAnalyticsFilter) -> list[NormalizedEvent]:
        """Return normalized events in the requested time window."""


@dataclass
class InMemoryThreatEventRepository:
    """In-memory event source used by tests and local app-state wiring."""

    events: list[NormalizedEvent]

    async def list_events(self, filters: ThreatAnalyticsFilter) -> list[NormalizedEvent]:
        return [
            event
            for event in self.events
            if filters.start_time <= event.event_time <= filters.end_time
            and (filters.tenant_id is None or event.tenant_id == filters.tenant_id)
        ]

