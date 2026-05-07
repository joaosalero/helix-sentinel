"""Security event ingestion API tests."""

from collections.abc import AsyncIterator
from dataclasses import dataclass

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.app import create_security_app
from app.audit.repositories import InMemoryAuditRepository
from app.events.repositories import InMemoryEventRepository


@dataclass
class EventApiContext:
    """Test wiring for the ingestion API."""

    client: AsyncClient
    events: InMemoryEventRepository
    audit: InMemoryAuditRepository


@pytest.fixture
async def event_context() -> AsyncIterator[EventApiContext]:
    app = create_security_app()
    event_repository = InMemoryEventRepository()
    audit_repository = InMemoryAuditRepository()
    app.state.event_repository = event_repository
    app.state.audit_repository = audit_repository

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield EventApiContext(client=client, events=event_repository, audit=audit_repository)


async def test_valid_event_ingestion_persists_raw_and_normalized(
    event_context: EventApiContext,
) -> None:
    response = await event_context.client.post(
        "/api/v1/events/ingest",
        headers={"X-Correlation-ID": "corr-ingest"},
        json={
            "source": {"name": "edr", "product": "endpoint", "vendor": "Acme"},
            "tenant_id": "tenant-a",
            "payload": {
                "event": {"action": "process started"},
                "severity": "medium",
                "host": {"name": "endpoint-01"},
                "process": {"name": "powershell.exe"},
            },
        },
    )

    assert response.status_code == 202
    body = response.json()
    assert body["category"] == "endpoint"
    assert body["severity"] == "medium"
    assert body["correlation_id"] == "corr-ingest"
    assert len(event_context.events.raw_events) == 1
    assert len(event_context.events.normalized_events) == 1
    assert event_context.events.raw_events[0].tenant_id == "tenant-a"
    assert event_context.events.normalized_events[0].asset.hostname == "endpoint-01"
    assert event_context.audit.events[-1].action == "events.ingested"


async def test_explicit_category_and_severity_are_preserved(event_context: EventApiContext) -> None:
    response = await event_context.client.post(
        "/api/v1/events/ingest",
        json={
            "source": {"name": "firewall"},
            "category": "network",
            "severity": "critical",
            "payload": {"message": "blocked connection", "src_ip": "10.0.0.5"},
        },
    )

    assert response.status_code == 202
    assert response.json()["category"] == "network"
    assert response.json()["severity"] == "critical"


async def test_malformed_json_is_rejected_and_audited(event_context: EventApiContext) -> None:
    response = await event_context.client.post(
        "/api/v1/events/ingest",
        content=b'{"source":',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Malformed JSON payload"}
    assert event_context.audit.events[-1].action == "events.validation_failed"
    assert event_context.audit.events[-1].metadata["reason"] == "malformed_json"


async def test_schema_validation_rejects_unknown_fields(event_context: EventApiContext) -> None:
    response = await event_context.client.post(
        "/api/v1/events/ingest",
        json={
            "source": {"name": "okta"},
            "payload": {"event": {"action": "login"}},
            "unexpected": True,
        },
    )

    assert response.status_code == 422
    assert event_context.audit.events[-1].metadata["reason"] == "schema_validation_failed"


async def test_empty_payload_is_rejected(event_context: EventApiContext) -> None:
    response = await event_context.client.post(
        "/api/v1/events/ingest",
        json={"source": {"name": "okta"}, "payload": {}},
    )

    assert response.status_code == 422
    assert len(event_context.events.raw_events) == 0


async def test_payload_size_limit_is_enforced(event_context: EventApiContext) -> None:
    oversized = b'{"source":{"name":"sensor"},"payload":{"message":"' + (b"a" * 300000) + b'"}}'

    response = await event_context.client.post(
        "/api/v1/events/ingest",
        content=oversized,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json() == {"detail": "Payload too large"}
    assert event_context.audit.events[-1].metadata["reason"] == "payload_too_large"


async def test_security_headers_are_present_on_ingestion(event_context: EventApiContext) -> None:
    response = await event_context.client.post(
        "/api/v1/events/ingest",
        headers={"X-Correlation-ID": "corr-secure"},
        json={"source": {"name": "sensor"}, "payload": {"message": "system health"}},
    )

    assert response.headers["X-Correlation-ID"] == "corr-secure"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"

