"""AI-assisted analytics API tests."""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.app import create_security_app
from app.auth.rbac import permissions_for_roles
from app.core.config.settings import SecuritySettings
from app.core.security.passwords import hash_password
from app.events.repositories import InMemoryEventRepository
from app.events.schemas import NormalizedEvent
from app.events.taxonomy import EventCategory, EventSeverity
from app.users.models import UserStatus
from app.users.repositories import InMemoryUserRepository
from app.users.schemas import StoredUser


@dataclass
class AIApiContext:
    """Test wiring for AI analytics API endpoints."""

    client: AsyncClient
    analyst_token: str
    denied_token: str


def _event(index: int, event_time: datetime) -> NormalizedEvent:
    return NormalizedEvent(
        id=uuid4(),
        raw_event_id=uuid4(),
        tenant_id="tenant-a",
        source_name="edr",
        source_product=None,
        source_vendor=None,
        category=EventCategory.ENDPOINT,
        severity=EventSeverity.HIGH,
        event_time=event_time,
        ingested_at=event_time,
        title="powershell encoded suspicious process",
    )


@pytest.fixture
async def ai_context() -> AsyncIterator[AIApiContext]:
    analyst_roles = frozenset({"analyst"})
    viewer_roles = frozenset({"viewer"})
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
    base = datetime(2026, 5, 8, 10, tzinfo=UTC)
    event_repository = InMemoryEventRepository()
    event_repository.normalized_events.extend(
        [_event(index, base + timedelta(minutes=index * 5)) for index in range(5)]
    )
    app = create_security_app()
    app.state.event_repository = event_repository
    app.state.user_repository = InMemoryUserRepository([analyst, viewer])
    app.state.security_settings = SecuritySettings(
        environment="test",
        auth_secret_key="test-access-secret-with-at-least-32-bytes",
        auth_refresh_secret_key="test-refresh-secret-with-at-least-32-bytes",
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        analyst_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "analyst@example.com", "password": "valid analyst password"},
        )
        viewer_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "viewer@example.com", "password": "valid viewer password"},
        )
        yield AIApiContext(
            client=client,
            analyst_token=analyst_login.json()["access_token"],
            denied_token=viewer_login.json()["access_token"],
        )


async def test_ai_anomalies_require_authentication(ai_context: AIApiContext) -> None:
    response = await ai_context.client.get("/api/v1/ai/anomalies")

    assert response.status_code == 401


async def test_ai_anomalies_enforce_analytics_permission(ai_context: AIApiContext) -> None:
    response = await ai_context.client.get(
        "/api/v1/ai/anomalies",
        headers={"Authorization": f"Bearer {ai_context.denied_token}"},
    )

    assert response.status_code == 403


async def test_ai_anomalies_support_filtering_and_pagination(ai_context: AIApiContext) -> None:
    response = await ai_context.client.get(
        "/api/v1/ai/anomalies",
        params={
            "start_time": "2026-05-08T09:00:00+00:00",
            "end_time": "2026-05-08T12:00:00+00:00",
            "anomaly_type": "event_burst",
            "limit": "1",
        },
        headers={"Authorization": f"Bearer {ai_context.analyst_token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["anomaly_type"] == "event_burst"


async def test_ai_enrichments_return_explainability(ai_context: AIApiContext) -> None:
    response = await ai_context.client.get(
        "/api/v1/ai/enrichments",
        params={
            "start_time": "2026-05-08T09:00:00+00:00",
            "end_time": "2026-05-08T12:00:00+00:00",
            "classification": "suspicious_process",
        },
        headers={"Authorization": f"Bearer {ai_context.analyst_token}"},
    )

    assert response.status_code == 200
    assert response.json()["total"] == 5
    assert response.json()["items"][0]["factors"]


async def test_invalid_ai_time_range_is_rejected(ai_context: AIApiContext) -> None:
    response = await ai_context.client.get(
        "/api/v1/ai/anomalies",
        params={
            "start_time": "2026-05-09T00:00:00+00:00",
            "end_time": "2026-05-08T00:00:00+00:00",
        },
        headers={"Authorization": f"Bearer {ai_context.analyst_token}"},
    )

    assert response.status_code == 422

