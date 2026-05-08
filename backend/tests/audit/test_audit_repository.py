"""Audit repository adapter tests."""

from uuid import uuid4

from app.audit.events import AuditAction, AuditEventCreate
from app.audit.repositories import PostgresAuditRepository, _to_audit_record
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
