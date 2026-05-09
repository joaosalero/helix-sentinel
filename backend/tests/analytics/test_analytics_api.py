"""Analytics API security and validation tests."""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import uuid4

import pytest
from fastapi import Request
from httpx import ASGITransport, AsyncClient

from app.analytics.repositories import PostgresAnalyticsRepository
from app.api.app import create_security_app
from app.api.routes.analytics import _analytics_repository
from app.auth.rbac import permissions_for_roles
from app.core.config.settings import SecuritySettings
from app.core.security.passwords import hash_password
from app.events.repositories import InMemoryEventRepository, PostgresEventRepository
from app.events.schemas import NormalizedActor, NormalizedAsset, NormalizedEvent
from app.events.taxonomy import EventCategory, EventSeverity
from app.users.models import UserStatus
from app.users.repositories import InMemoryUserRepository
from app.users.schemas import StoredUser


@dataclass
class AnalyticsApiContext:
    """Test wiring for analytics API endpoints."""

    client: AsyncClient
    analyst_token: str
    denied_token: str


def _normalized_event(
    category: EventCategory,
    severity: EventSeverity,
    source: str,
    event_time: datetime,
    title: str = "event",
) -> NormalizedEvent:
    return NormalizedEvent(
        id=uuid4(),
        raw_event_id=uuid4(),
        tenant_id="tenant-a",
        source_name=source,
        source_product=None,
        source_vendor=None,
        category=category,
        severity=severity,
        event_time=event_time,
        ingested_at=event_time,
        title=title,
    )


@pytest.fixture
async def analytics_context() -> AsyncIterator[AnalyticsApiContext]:
    analyst_roles = frozenset({"analyst"})
    denied_roles = frozenset({"viewer"})
    analyst = StoredUser(
        id=uuid4(),
        tenant_id="tenant-a",
        email="analyst@example.com",
        display_name="Analyst",
        password_hash=hash_password("valid analyst password"),
        status=UserStatus.ACTIVE,
        roles=analyst_roles,
        permissions=permissions_for_roles(analyst_roles),
    )
    denied = StoredUser(
        id=uuid4(),
        tenant_id="tenant-a",
        email="viewer@example.com",
        display_name="Viewer",
        password_hash=hash_password("valid viewer password"),
        status=UserStatus.ACTIVE,
        roles=denied_roles,
        permissions=frozenset(),
    )
    base = datetime(2026, 5, 7, tzinfo=UTC)
    event_repository = InMemoryEventRepository()
    event_repository.normalized_events.extend(
        [
            _normalized_event(
                EventCategory.AUTHENTICATION,
                EventSeverity.HIGH,
                "okta",
                base,
                "login failed",
            ),
            _normalized_event(EventCategory.ENDPOINT, EventSeverity.CRITICAL, "edr", base),
            _normalized_event(
                EventCategory.NETWORK,
                EventSeverity.MEDIUM,
                "firewall",
                base + timedelta(days=1),
            ),
        ]
    )
    event_repository.normalized_events.append(
        NormalizedEvent(
            id=uuid4(),
            raw_event_id=uuid4(),
            tenant_id="tenant-a",
            source_name="edr",
            source_product="endpoint",
            source_vendor="Acme",
            category=EventCategory.ENDPOINT,
            severity=EventSeverity.HIGH,
            event_time=base + timedelta(hours=1),
            ingested_at=base + timedelta(hours=1),
            title="powershell process",
            actor=NormalizedActor(username="alice", ip_address="10.0.0.9"),
            asset=NormalizedAsset(hostname="workstation-7"),
            ioc={"indicator": "bad.example"},
        )
    )
    event_repository.normalized_events.append(
        NormalizedEvent(
            id=uuid4(),
            raw_event_id=uuid4(),
            tenant_id="tenant-b",
            source_name="edr",
            source_product="endpoint",
            source_vendor="Acme",
            category=EventCategory.ENDPOINT,
            severity=EventSeverity.HIGH,
            event_time=base + timedelta(hours=1),
            ingested_at=base + timedelta(hours=1),
            title="powershell process",
            actor=NormalizedActor(username="alice", ip_address="10.0.0.9"),
            asset=NormalizedAsset(hostname="blocked-host"),
            ioc={"indicator": "bad.example"},
        )
    )
    app = create_security_app()
    app.state.event_repository = event_repository
    app.state.user_repository = InMemoryUserRepository([analyst, denied])
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
        denied_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "viewer@example.com", "password": "valid viewer password"},
        )
        yield AnalyticsApiContext(
            client=client,
            analyst_token=analyst_login.json()["access_token"],
            denied_token=denied_login.json()["access_token"],
        )


async def test_overview_endpoint_requires_authentication(
    analytics_context: AnalyticsApiContext,
) -> None:
    response = await analytics_context.client.get("/api/v1/analytics/overview")

    assert response.status_code == 401


async def test_overview_endpoint_enforces_analytics_permission(
    analytics_context: AnalyticsApiContext,
) -> None:
    response = await analytics_context.client.get(
        "/api/v1/analytics/overview",
        headers={"Authorization": f"Bearer {analytics_context.denied_token}"},
    )

    assert response.status_code == 403


async def test_overview_endpoint_returns_dashboard_ready_metrics(
    analytics_context: AnalyticsApiContext,
) -> None:
    response = await analytics_context.client.get(
        "/api/v1/analytics/overview",
        params={
            "start_time": "2026-05-06T00:00:00+00:00",
            "end_time": "2026-05-09T00:00:00+00:00",
        },
        headers={"Authorization": f"Bearer {analytics_context.analyst_token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total_events"] == 4
    assert body["kpis"]["high_severity_ratio"] == 0.75
    assert len(body["top_sources"]) == 3


async def test_severity_endpoint_supports_date_filtering(
    analytics_context: AnalyticsApiContext,
) -> None:
    response = await analytics_context.client.get(
        "/api/v1/analytics/severity",
        params={
            "start_time": "2026-05-07T00:00:00+00:00",
            "end_time": "2026-05-07T23:59:00+00:00",
        },
        headers={"Authorization": f"Bearer {analytics_context.analyst_token}"},
    )

    assert response.status_code == 200
    counts = {item["name"]: item["count"] for item in response.json()}
    assert counts["high"] == 2
    assert counts["critical"] == 1
    assert counts["medium"] == 0


async def test_sources_endpoint_supports_pagination(
    analytics_context: AnalyticsApiContext,
) -> None:
    response = await analytics_context.client.get(
        "/api/v1/analytics/sources",
        params={
            "start_time": "2026-05-06T00:00:00+00:00",
            "end_time": "2026-05-09T00:00:00+00:00",
            "limit": "1",
        },
        headers={"Authorization": f"Bearer {analytics_context.analyst_token}"},
    )

    assert response.status_code == 200
    assert len(response.json()) == 1


async def test_event_search_supports_investigation_filters(
    analytics_context: AnalyticsApiContext,
) -> None:
    response = await analytics_context.client.get(
        "/api/v1/analytics/events",
        params={
            "start_time": "2026-05-06T00:00:00+00:00",
            "end_time": "2026-05-09T00:00:00+00:00",
            "source_product": "endpoint",
            "title": "powershell",
            "actor_username": "alice",
            "ioc_value": "bad.example",
        },
        headers={"Authorization": f"Bearer {analytics_context.analyst_token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["limit"] == 50
    assert len(body["items"]) == 1
    assert body["items"][0]["tenant_id"] == "tenant-a"
    assert body["items"][0]["actor"]["username"] == "alice"


async def test_event_search_uses_principal_tenant_by_default(
    analytics_context: AnalyticsApiContext,
) -> None:
    response = await analytics_context.client.get(
        "/api/v1/analytics/events",
        params={
            "start_time": "2026-05-06T00:00:00+00:00",
            "end_time": "2026-05-09T00:00:00+00:00",
            "source": "okta",
        },
        headers={"Authorization": f"Bearer {analytics_context.analyst_token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body["items"]) == 1
    assert body["items"][0]["tenant_id"] == "tenant-a"


async def test_invalid_time_range_is_rejected(analytics_context: AnalyticsApiContext) -> None:
    response = await analytics_context.client.get(
        "/api/v1/analytics/overview",
        params={
            "start_time": "2026-05-09T00:00:00+00:00",
            "end_time": "2026-05-06T00:00:00+00:00",
        },
        headers={"Authorization": f"Bearer {analytics_context.analyst_token}"},
    )

    assert response.status_code == 422


async def test_cross_tenant_analytics_filter_is_rejected(
    analytics_context: AnalyticsApiContext,
) -> None:
    response = await analytics_context.client.get(
        "/api/v1/analytics/overview",
        params={
            "start_time": "2026-05-06T00:00:00+00:00",
            "end_time": "2026-05-09T00:00:00+00:00",
            "tenant_id": "tenant-b",
        },
        headers={"Authorization": f"Bearer {analytics_context.analyst_token}"},
    )

    assert response.status_code == 403


async def test_postgres_event_repository_uses_postgres_analytics_repository() -> None:
    app = create_security_app()
    app.state.event_repository = PostgresEventRepository(app.state.db_session_factory)
    request = _RequestStub(app)

    repository = await _analytics_repository(cast(Request, request))

    assert isinstance(repository, PostgresAnalyticsRepository)


@dataclass
class _RequestStub:
    app: object
