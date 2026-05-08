"""Threat Analytics API tests."""

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
from app.enrichment.repositories import InMemoryIOCRepository
from app.enrichment.schemas import EventIOCMatch, IOCCreateRequest
from app.enrichment.taxonomy import EnrichmentStatus, IndicatorType
from app.events.repositories import InMemoryEventRepository
from app.events.schemas import NormalizedActor, NormalizedEvent
from app.events.taxonomy import EventCategory, EventSeverity
from app.users.models import UserStatus
from app.users.repositories import InMemoryUserRepository
from app.users.schemas import StoredUser


@dataclass
class ThreatApiContext:
    """Test wiring for Threat Analytics APIs."""

    client: AsyncClient
    analyst_token: str
    denied_token: str


def _event(index: int, event_time: datetime) -> NormalizedEvent:
    return NormalizedEvent(
        id=uuid4(),
        raw_event_id=uuid4(),
        tenant_id="tenant-a",
        source_name="okta",
        source_product=None,
        source_vendor=None,
        category=EventCategory.AUTHENTICATION,
        severity=EventSeverity.HIGH,
        event_time=event_time,
        ingested_at=event_time,
        title="login failed",
        actor=NormalizedActor(email=f"user{index % 2}@example.com", ip_address="203.0.113.50"),
    )


@pytest.fixture
async def threat_context() -> AsyncIterator[ThreatApiContext]:
    analyst_roles = frozenset({"analyst"})
    viewer_roles = frozenset({"viewer"})
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
    viewer = StoredUser(
        id=uuid4(),
        tenant_id="tenant-a",
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
    ioc_repository = InMemoryIOCRepository()
    ioc = await ioc_repository.create(
        IOCCreateRequest(
            indicator_type=IndicatorType.IP,
            value="203.0.113.50",
            confidence=85,
            severity="high",
            source_name="internal-ti",
            source_reliability="verified",
        )
    )
    await ioc_repository.store_matches(
        [
            EventIOCMatch(
                event_id=event_repository.normalized_events[0].id,
                ioc_id=ioc.id,
                indicator_type=IndicatorType.IP,
                value=ioc.value,
                status=EnrichmentStatus.MATCHED,
                confidence=90,
                confidence_factors=[],
                matched_fields=["actor.ip_address"],
                metadata={"tenant_id": "tenant-a"},
            )
        ]
    )
    app = create_security_app()
    app.state.event_repository = event_repository
    app.state.ioc_repository = ioc_repository
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
        yield ThreatApiContext(
            client=client,
            analyst_token=analyst_login.json()["access_token"],
            denied_token=viewer_login.json()["access_token"],
        )


async def test_threat_insights_require_authentication(threat_context: ThreatApiContext) -> None:
    response = await threat_context.client.get("/api/v1/threats/insights")

    assert response.status_code == 401


async def test_threat_insights_enforce_analytics_permission(
    threat_context: ThreatApiContext,
) -> None:
    response = await threat_context.client.get(
        "/api/v1/threats/insights",
        headers={"Authorization": f"Bearer {threat_context.denied_token}"},
    )

    assert response.status_code == 403


async def test_threat_insights_support_filtering_and_pagination(
    threat_context: ThreatApiContext,
) -> None:
    response = await threat_context.client.get(
        "/api/v1/threats/insights",
        params={
            "start_time": "2026-05-08T09:00:00+00:00",
            "end_time": "2026-05-08T12:00:00+00:00",
            "insight_type": "suspicious_ip_reuse",
            "limit": "1",
        },
        headers={"Authorization": f"Bearer {threat_context.analyst_token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["insight_type"] == "suspicious_ip_reuse"


async def test_threat_summary_returns_counts(threat_context: ThreatApiContext) -> None:
    response = await threat_context.client.get(
        "/api/v1/threats/summary",
        params={
            "start_time": "2026-05-08T09:00:00+00:00",
            "end_time": "2026-05-08T12:00:00+00:00",
        },
        headers={"Authorization": f"Bearer {threat_context.analyst_token}"},
    )

    assert response.status_code == 200
    assert response.json()["suspicious_ip_reuse"] == 1
    assert response.json()["total_insights"] >= 1


async def test_ioc_activity_returns_tenant_scoped_match_analytics(
    threat_context: ThreatApiContext,
) -> None:
    response = await threat_context.client.get(
        "/api/v1/threats/ioc-activity",
        params={
            "start_time": "2026-05-08T00:00:00+00:00",
            "end_time": "2026-05-09T00:00:00+00:00",
            "indicator_type": "ip",
            "min_confidence": "80",
        },
        headers={"Authorization": f"Bearer {threat_context.analyst_token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total_matches"] == 1
    assert body["matched_events"] == 1
    assert body["high_confidence_matches"] == 1
    assert body["top_iocs"][0]["value"] == "203.0.113.50"


async def test_invalid_threat_time_range_is_rejected(threat_context: ThreatApiContext) -> None:
    response = await threat_context.client.get(
        "/api/v1/threats/insights",
        params={
            "start_time": "2026-05-09T00:00:00+00:00",
            "end_time": "2026-05-08T00:00:00+00:00",
        },
        headers={"Authorization": f"Bearer {threat_context.analyst_token}"},
    )

    assert response.status_code == 422


async def test_cross_tenant_threat_filter_is_rejected(
    threat_context: ThreatApiContext,
) -> None:
    response = await threat_context.client.get(
        "/api/v1/threats/insights",
        params={
            "start_time": "2026-05-08T09:00:00+00:00",
            "end_time": "2026-05-08T12:00:00+00:00",
            "tenant_id": "tenant-b",
        },
        headers={"Authorization": f"Bearer {threat_context.analyst_token}"},
    )

    assert response.status_code == 403
