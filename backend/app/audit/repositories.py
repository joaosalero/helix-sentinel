"""Audit repository protocols and in-memory implementation."""

from typing import Protocol

from app.audit.events import AuditEventCreate


class AuditRepository(Protocol):
    """Append-only audit event boundary."""

    async def append(self, event: AuditEventCreate) -> None:
        """Persist or emit a sanitized audit event."""


class InMemoryAuditRepository:
    """Test/local audit repository that retains structured audit events."""

    def __init__(self) -> None:
        self.events: list[AuditEventCreate] = []

    async def append(self, event: AuditEventCreate) -> None:
        self.events.append(event)

