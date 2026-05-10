"""Audit repository adapter tests."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.audit.events import AuditAction, AuditEventCreate
from app.audit.repositories import (
    InMemoryAuditRepository,
    PostgresAuditRepository,
    _to_audit_record,
)
from app.audit.schemas import AuditActivityFilter
from helix_sentinel.core.config import Settings
from helix_sentinel.main import create_app


def test_authoritative_runtime_uses_postgres_audit_repository() -> None:
    app = create_app(
        Settings(
            environment="test",
            secret_key="test-secret-key-with-at-least-32-bytes",
            database_url="postgresql+asyncpg://helix:helix@localhost:5432/helix_sentinel_test",
        )
    )

    assert isinstance(app.state.audit_repository, PostgresAuditRepository)


def test_audit_repository_maps_event_without_changing_security_fields() -> None:
    actor_id = uuid4()
    event = AuditEventCreate(
        action=AuditAction.LOGIN_FAILED,
        outcome="failure",
        actor_id=actor_id,
        actor_email_hash="hashed-email",
        resource="auth",
        correlation_id="corr-audit",
        metadata={"reason": "invalid_credentials_or_state", "password": "[redacted]"},
    )

    record = _to_audit_record(event)

    assert record.action == AuditAction.LOGIN_FAILED.value
    assert record.outcome == "failure"
    assert record.actor_id == actor_id
    assert record.actor_email_hash == "hashed-email"
    assert record.resource == "auth"
    assert record.correlation_id == "corr-audit"
    assert record.metadata_["password"] == "[redacted]"
    assert record.created_at == event.created_at


async def test_in_memory_audit_activity_applies_time_and_tenant_scope() -> None:
    repository = InMemoryAuditRepository()
    actor_id = uuid4()
    base = datetime(2026, 5, 7, tzinfo=UTC)
    await repository.append(
        AuditEventCreate(
            action=AuditAction.LOGIN_SUCCEEDED,
            outcome="success",
            actor_id=actor_id,
            actor_email_hash="hash-a",
            metadata={"tenant_id": "tenant-a"},
            created_at=base,
        )
    )
    await repository.append(
        AuditEventCreate(
            action=AuditAction.DETECTION_ALERT_UPDATED,
            outcome="success",
            actor_id=actor_id,
            metadata={"tenant_id": "tenant-a", "to_status": "closed"},
            created_at=base + timedelta(hours=1),
        )
    )
    await repository.append(
        AuditEventCreate(
            action=AuditAction.LOGIN_FAILED,
            outcome="failure",
            metadata={"tenant_id": "tenant-b"},
            created_at=base + timedelta(hours=2),
        )
    )

    summary = await repository.security_activity_summary(
        AuditActivityFilter(
            start_time=base - timedelta(minutes=1),
            end_time=base + timedelta(hours=2),
            tenant_id="tenant-a",
        )
    )

    assert summary.total_audit_events == 2
    assert summary.authentication.successes == 1
    assert summary.investigations.closures == 1
    assert summary.active_actor_count == 1
    assert summary.recent_activity[0].action == AuditAction.DETECTION_ALERT_UPDATED.value
