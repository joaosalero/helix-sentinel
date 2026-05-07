"""IOC enrichment API tests."""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.app import create_security_app
from app.auth.rbac import permissions_for_roles
from app.core.config.settings import SecuritySettings
from app.core.security.passwords import hash_password
from app.enrichment.repositories import InMemoryIOCRepository
from app.events.repositories import InMemoryEventRepository
from app.events.schemas import NormalizedActor, NormalizedEvent
from app.events.taxonomy import EventCategory, EventSeverity
from app.users.models import UserStatus
from app.users.repositories import InMemoryUserRepository
from app.users.schemas import StoredUser


@dataclass
class EnrichmentApiContext:
    """Test wiring for IOC enrichment APIs."""

    client: AsyncClient
    engineer_token: str
    analyst_token: str
    denied_token: str
    iocs: InMemoryIOCRepository


def _event() -> NormalizedEvent:
    now = datetime(2026, 5, 8, 12, tzinfo=UTC)
    return NormalizedEvent(
        id=uuid4(),
        raw_event_id=uuid4(),
        tenant_id="tenant-a",
        source_name="edr",
        source_product=None,
        source_vendor=None,
        category=EventCategory.ENDPOINT,
        severity=EventSeverity.HIGH,
        event_time=now,
        ingested_at=now,
        title="endpoint contacted known bad address",
        actor=NormalizedActor(ip_address="203.0.113.10"),
        ioc={"url": "https://evil.example/dropper"},
    )


@pytest.fixture
async def enrichment_context() -> AsyncIterator[EnrichmentApiContext]:
    engineer_roles = frozenset({"engineer"})
    analyst_roles = frozenset({"analyst"})
    viewer_roles = frozenset({"viewer"})
    engineer = StoredUser(
        id=uuid4(),
        email="engineer@example.com",
        display_name="Engineer",
        password_hash=hash_password("valid engineer password"),
        status=UserStatus.ACTIVE,
        roles=engineer_roles,
        permissions=permissions_for_roles(engineer_roles),
    )
    analyst = StoredUser(
        id=uuid4(),
        email="analyst@example.com",
        display_name="Analyst",
        password_hash=hash_password("valid analyst password"),
        status=UserStatus.ACTIVE,
        roles=analyst_roles,
        permissions=permissions_for_roles(analyst_roles),
    )
    viewer = StoredUser(
        id=uuid4(),
        email="viewer@example.com",
        display_name="Viewer",
        password_hash=hash_password("valid viewer password"),
        status=UserStatus.ACTIVE,
        roles=viewer_roles,
        permissions=frozenset(),
    )
    event_repository = InMemoryEventRepository()
    event_repository.normalized_events.append(_event())
    ioc_repository = InMemoryIOCRepository()
    app = create_security_app()
    app.state.event_repository = event_repository
    app.state.ioc_repository = ioc_repository
    app.state.user_repository = InMemoryUserRepository([engineer, analyst, viewer])
    app.state.security_settings = SecuritySettings(
        environment="test",
        auth_secret_key="test-access-secret-with-at-least-32-bytes",
        auth_refresh_secret_key="test-refresh-secret-with-at-least-32-bytes",
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        engineer_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "engineer@example.com", "password": "valid engineer password"},
        )
        analyst_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "analyst@example.com", "password": "valid analyst password"},
        )
        viewer_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "viewer@example.com", "password": "valid viewer password"},
        )
        yield EnrichmentApiContext(
            client=client,
            engineer_token=engineer_login.json()["access_token"],
            analyst_token=analyst_login.json()["access_token"],
            denied_token=viewer_login.json()["access_token"],
            iocs=ioc_repository,
        )


async def test_ioc_creation_requires_write_permission(
    enrichment_context: EnrichmentApiContext,
) -> None:
    response = await enrichment_context.client.post(
        "/api/v1/enrichment/iocs",
        headers={"Authorization": f"Bearer {enrichment_context.denied_token}"},
        json={
            "indicator_type": "ip",
            "value": "203.0.113.10",
            "source_name": "internal-curation",
        },
    )

    assert response.status_code == 403


async def test_ioc_creation_rejects_malicious_local_url(
    enrichment_context: EnrichmentApiContext,
) -> None:
    response = await enrichment_context.client.post(
        "/api/v1/enrichment/iocs",
        headers={"Authorization": f"Bearer {enrichment_context.engineer_token}"},
        json={
            "indicator_type": "url",
            "value": "http://127.0.0.1/admin",
            "source_name": "internal-curation",
        },
    )

    assert response.status_code == 422
    assert len(enrichment_context.iocs.iocs) == 0


async def test_ioc_create_list_detail_and_summary(
    enrichment_context: EnrichmentApiContext,
) -> None:
    create_response = await enrichment_context.client.post(
        "/api/v1/enrichment/iocs",
        headers={"Authorization": f"Bearer {enrichment_context.engineer_token}"},
        json={
            "indicator_type": "ip",
            "value": "203.0.113.10",
            "confidence": 85,
            "severity": "high",
            "source_name": "internal-curation",
            "source_reliability": "high",
            "tags": ["endpoint"],
        },
    )
    assert create_response.status_code == 201
    ioc_id = create_response.json()["id"]

    list_response = await enrichment_context.client.get(
        "/api/v1/enrichment/iocs",
        params={"indicator_type": "ip", "min_confidence": "80"},
        headers={"Authorization": f"Bearer {enrichment_context.analyst_token}"},
    )
    detail_response = await enrichment_context.client.get(
        f"/api/v1/enrichment/iocs/{ioc_id}",
        headers={"Authorization": f"Bearer {enrichment_context.analyst_token}"},
    )
    summary_response = await enrichment_context.client.get(
        "/api/v1/enrichment/summary",
        headers={"Authorization": f"Bearer {enrichment_context.analyst_token}"},
    )

    assert list_response.status_code == 200
    assert list_response.json()["total"] == 1
    assert detail_response.status_code == 200
    assert detail_response.json()["value"] == "203.0.113.10"
    assert summary_response.status_code == 200
    assert summary_response.json()["high_confidence_iocs"] == 1


async def test_enrichment_execution_matches_stored_events(
    enrichment_context: EnrichmentApiContext,
) -> None:
    await enrichment_context.client.post(
        "/api/v1/enrichment/iocs",
        headers={"Authorization": f"Bearer {enrichment_context.engineer_token}"},
        json={
            "indicator_type": "ip",
            "value": "203.0.113.10",
            "confidence": 80,
            "severity": "high",
            "source_name": "internal-curation",
            "source_reliability": "verified",
        },
    )

    response = await enrichment_context.client.post(
        "/api/v1/enrichment/execute",
        headers={"Authorization": f"Bearer {enrichment_context.analyst_token}"},
        json={"tenant_id": "tenant-a"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "matched"
    assert body["total_matches"] == 1
    assert body["matches"][0]["confidence_factors"]


async def test_enrichment_query_validation_is_enforced(
    enrichment_context: EnrichmentApiContext,
) -> None:
    response = await enrichment_context.client.get(
        "/api/v1/enrichment/iocs",
        params={"limit": "1000"},
        headers={"Authorization": f"Bearer {enrichment_context.analyst_token}"},
    )

    assert response.status_code == 422
