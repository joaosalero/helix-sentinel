"""Audit repository protocols and in-memory implementation."""

from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.audit.events import AuditEventCreate
from app.audit.models import AuditEvent


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


class PostgresAuditRepository:
    """PostgreSQL-backed append-only audit repository."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def append(self, event: AuditEventCreate) -> None:
        async with self.session_factory() as session, session.begin():
            session.add(_to_audit_record(event))


def _to_audit_record(event: AuditEventCreate) -> AuditEvent:
    return AuditEvent(
        action=event.action.value,
        outcome=event.outcome,
        actor_id=event.actor_id,
        actor_email_hash=event.actor_email_hash,
        resource=event.resource,
        correlation_id=event.correlation_id,
        metadata_=event.metadata,
    )
