"""Detection Engineering API tests."""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.app import create_security_app
from app.auth.rbac import permissions_for_roles
from app.core.config.settings import SecuritySettings
from app.core.security.passwords import hash_password
from app.detections.repositories import (
    InMemoryDetectionAlertRepository,
    InMemoryDetectionRuleRepository,
)
from app.events.repositories import InMemoryEventRepository
from app.events.schemas import NormalizedEvent
from app.events.taxonomy import EventCategory, EventSeverity
from app.users.models import UserStatus
from app.users.repositories import InMemoryUserRepository
from app.users.schemas import StoredUser

SIGMA_RULE = """
title: Suspicious PowerShell Execution
id: 8f7c2f10-1111-4444-8888-123456789abc
status: test
description: Detects suspicious PowerShell command usage.
author: SOC Team
references:
  - https://example.com/research
tags:
  - attack.execution
  - attack.t1059.001
  - windows
logsource:
  product: windows
  category: process_creation
level: high
falsepositives:
  - Administrative scripts
detection:
  selection:
    Image|endswith: '\\powershell.exe'
  condition: selection
"""

NETWORK_RULE = """
title: Suspicious DNS Query
tags:
  - attack.command_and_control
  - attack.t1071.004
logsource:
  product: firewall
  category: dns
level: medium
detection:
  selection:
    query: bad.example
  condition: selection
"""

EXECUTION_RULE = """
title: Suspicious PowerShell Title Match
tags:
  - attack.execution
logsource:
  product: windows
  category: process_creation
level: high
detection:
  selection:
    title|contains: powershell
  condition: selection
"""


@dataclass
class DetectionApiContext:
    """Test wiring for Detection Engineering APIs."""

    client: AsyncClient
    engineer_token: str
    analyst_token: str
    viewer_token: str
    repository: InMemoryDetectionRuleRepository
    alert_repository: InMemoryDetectionAlertRepository


@pytest.fixture
async def detection_context() -> AsyncIterator[DetectionApiContext]:
    engineer_roles = frozenset({"engineer"})
    analyst_roles = frozenset({"analyst"})
    viewer_roles = frozenset({"viewer"})
    engineer = StoredUser(
        id=uuid4(),
        tenant_id="tenant-a",
        email="engineer@example.com",
        display_name="Detection Engineer",
        password_hash=hash_password("valid engineer password"),
        status=UserStatus.ACTIVE,
        roles=engineer_roles,
        permissions=permissions_for_roles(engineer_roles),
    )
    viewer = StoredUser(
        id=uuid4(),
        tenant_id="tenant-a",
        email="viewer@example.com",
        display_name="Viewer",
        password_hash=hash_password("valid viewer password"),
        status=UserStatus.ACTIVE,
        roles=viewer_roles,
        permissions=permissions_for_roles(viewer_roles),
    )
    analyst = StoredUser(
        id=uuid4(),
        tenant_id="tenant-a",
        email="analyst@example.com",
        display_name="SOC Analyst",
        password_hash=hash_password("valid analyst password"),
        status=UserStatus.ACTIVE,
        roles=analyst_roles,
        permissions=permissions_for_roles(analyst_roles),
    )
    repository = InMemoryDetectionRuleRepository()
    alert_repository = InMemoryDetectionAlertRepository()
    event_repository = InMemoryEventRepository()
    event_repository.normalized_events.append(
        NormalizedEvent(
            id=uuid4(),
            raw_event_id=uuid4(),
            tenant_id="tenant-a",
            source_name="edr",
            source_product="windows",
            source_vendor=None,
            category=EventCategory.ENDPOINT,
            severity=EventSeverity.HIGH,
            event_time=datetime(2026, 5, 8, 12, tzinfo=UTC),
            ingested_at=datetime(2026, 5, 8, 12, tzinfo=UTC),
            title="powershell encoded suspicious process",
        )
    )
    app = create_security_app()
    app.state.user_repository = InMemoryUserRepository([engineer, analyst, viewer])
    app.state.detection_rule_repository = repository
    app.state.detection_alert_repository = alert_repository
    app.state.event_repository = event_repository
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
        viewer_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "viewer@example.com", "password": "valid viewer password"},
        )
        analyst_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "analyst@example.com", "password": "valid analyst password"},
        )
        yield DetectionApiContext(
            client=client,
            engineer_token=engineer_login.json()["access_token"],
            analyst_token=analyst_login.json()["access_token"],
            viewer_token=viewer_login.json()["access_token"],
            repository=repository,
            alert_repository=alert_repository,
        )


async def _import_rule(
    context: DetectionApiContext,
    content: str,
    status: str = "draft",
) -> dict[str, Any]:
    response = await context.client.post(
        "/api/v1/detections/rules/sigma",
        headers={"Authorization": f"Bearer {context.engineer_token}"},
        json={"content": content, "status": status},
    )
    assert response.status_code == 201
    return cast(dict[str, Any], response.json())


async def test_sigma_import_requires_write_permission(
    detection_context: DetectionApiContext,
) -> None:
    response = await detection_context.client.post(
        "/api/v1/detections/rules/sigma",
        headers={"Authorization": f"Bearer {detection_context.viewer_token}"},
        json={"content": SIGMA_RULE},
    )

    assert response.status_code == 403


async def test_sigma_import_persists_normalized_rule(
    detection_context: DetectionApiContext,
) -> None:
    body = await _import_rule(detection_context, SIGMA_RULE, status="active")

    assert body["title"] == "Suspicious PowerShell Execution"
    assert body["status"] == "active"
    assert body["severity"] == "high"
    assert body["category"] == "endpoint"
    assert body["attack"][0]["technique_id"] == "T1059.001"
    assert len(detection_context.repository.rules) == 1


async def test_malformed_sigma_is_rejected_and_not_persisted(
    detection_context: DetectionApiContext,
) -> None:
    response = await detection_context.client.post(
        "/api/v1/detections/rules/sigma",
        headers={"Authorization": f"Bearer {detection_context.engineer_token}"},
        json={"content": "title: Missing Detection"},
    )

    assert response.status_code == 422
    assert len(detection_context.repository.rules) == 0


async def test_upload_validation_rejects_unknown_fields(
    detection_context: DetectionApiContext,
) -> None:
    response = await detection_context.client.post(
        "/api/v1/detections/rules/sigma",
        headers={"Authorization": f"Bearer {detection_context.engineer_token}"},
        json={"content": SIGMA_RULE, "unexpected": True},
    )

    assert response.status_code == 422


async def test_rule_listing_filters_by_severity_tag_and_attack(
    detection_context: DetectionApiContext,
) -> None:
    await _import_rule(detection_context, SIGMA_RULE)
    await _import_rule(detection_context, NETWORK_RULE)

    response = await detection_context.client.get(
        "/api/v1/detections/rules",
        headers={"Authorization": f"Bearer {detection_context.engineer_token}"},
        params={"severity": "high", "tag": "windows", "attack_technique": "T1059.001"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["title"] == "Suspicious PowerShell Execution"


async def test_rule_listing_filters_by_title_and_source(
    detection_context: DetectionApiContext,
) -> None:
    await _import_rule(detection_context, SIGMA_RULE)
    await _import_rule(detection_context, NETWORK_RULE)

    response = await detection_context.client.get(
        "/api/v1/detections/rules",
        headers={"Authorization": f"Bearer {detection_context.engineer_token}"},
        params={"title": "powershell", "source": "windows:process_creation"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["title"] == "Suspicious PowerShell Execution"


async def test_rule_listing_paginates(detection_context: DetectionApiContext) -> None:
    await _import_rule(detection_context, SIGMA_RULE)
    await _import_rule(detection_context, NETWORK_RULE)

    response = await detection_context.client.get(
        "/api/v1/detections/rules",
        headers={"Authorization": f"Bearer {detection_context.engineer_token}"},
        params={"limit": "1", "offset": "1"},
    )

    assert response.status_code == 200
    assert response.json()["limit"] == 1
    assert len(response.json()["items"]) == 1


async def test_rule_detail_retrieval(detection_context: DetectionApiContext) -> None:
    body = await _import_rule(detection_context, SIGMA_RULE)
    rule_id = UUID(str(body["id"]))

    response = await detection_context.client.get(
        f"/api/v1/detections/rules/{rule_id}",
        headers={"Authorization": f"Bearer {detection_context.engineer_token}"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == str(rule_id)


async def test_rule_listing_requires_authentication(
    detection_context: DetectionApiContext,
) -> None:
    response = await detection_context.client.get("/api/v1/detections/rules")

    assert response.status_code == 401


async def test_active_rule_execution_matches_bounded_events(
    detection_context: DetectionApiContext,
) -> None:
    body = await _import_rule(detection_context, EXECUTION_RULE, status="active")

    response = await detection_context.client.post(
        f"/api/v1/detections/rules/{body['id']}/execute",
        headers={"Authorization": f"Bearer {detection_context.engineer_token}"},
        json={
            "start_time": "2026-05-08T00:00:00+00:00",
            "end_time": "2026-05-09T00:00:00+00:00",
            "tenant_id": "tenant-a",
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["evaluated_events"] == 1
    assert result["matched_events"] == 1
    assert result["matches"][0]["matched_selections"] == ["selection"]
    assert len(detection_context.alert_repository.alerts) == 1
    alert = detection_context.alert_repository.alerts[0]
    assert alert.tenant_id == "tenant-a"
    assert alert.rule_id == UUID(str(body["id"]))
    assert alert.status == "open"


async def test_alert_queue_lists_tenant_scoped_persisted_alerts(
    detection_context: DetectionApiContext,
) -> None:
    body = await _import_rule(detection_context, EXECUTION_RULE, status="active")
    await detection_context.client.post(
        f"/api/v1/detections/rules/{body['id']}/execute",
        headers={"Authorization": f"Bearer {detection_context.engineer_token}"},
        json={
            "start_time": "2026-05-08T00:00:00+00:00",
            "end_time": "2026-05-09T00:00:00+00:00",
            "tenant_id": "tenant-a",
        },
    )

    response = await detection_context.client.get(
        "/api/v1/detections/alerts",
        headers={"Authorization": f"Bearer {detection_context.analyst_token}"},
        params={"status": "open"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"][0]["tenant_id"] == "tenant-a"
    assert payload["items"][0]["status"] == "open"


async def test_alert_queue_filters_by_investigation_context(
    detection_context: DetectionApiContext,
) -> None:
    body = await _import_rule(detection_context, EXECUTION_RULE, status="active")
    await detection_context.client.post(
        f"/api/v1/detections/rules/{body['id']}/execute",
        headers={"Authorization": f"Bearer {detection_context.engineer_token}"},
        json={
            "start_time": "2026-05-08T00:00:00+00:00",
            "end_time": "2026-05-09T00:00:00+00:00",
            "tenant_id": "tenant-a",
        },
    )
    alert = detection_context.alert_repository.alerts[0]

    response = await detection_context.client.get(
        "/api/v1/detections/alerts",
        headers={"Authorization": f"Bearer {detection_context.analyst_token}"},
        params={
            "category": "endpoint",
            "source": "edr",
            "rule_id": str(alert.rule_id),
            "event_id": str(alert.event_id),
            "start_time": "2026-05-08T00:00:00+00:00",
            "end_time": "2026-05-09T00:00:00+00:00",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"][0]["id"] == str(alert.id)


async def test_detection_coverage_returns_attack_and_rule_efficacy(
    detection_context: DetectionApiContext,
) -> None:
    await _import_rule(detection_context, SIGMA_RULE, status="active")
    await _import_rule(detection_context, NETWORK_RULE, status="draft")
    execution_rule = await _import_rule(detection_context, EXECUTION_RULE, status="active")
    await detection_context.client.post(
        f"/api/v1/detections/rules/{execution_rule['id']}/execute",
        headers={"Authorization": f"Bearer {detection_context.engineer_token}"},
        json={
            "start_time": "2026-05-08T00:00:00+00:00",
            "end_time": "2026-05-09T00:00:00+00:00",
            "tenant_id": "tenant-a",
        },
    )

    response = await detection_context.client.get(
        "/api/v1/detections/coverage",
        headers={"Authorization": f"Bearer {detection_context.analyst_token}"},
        params={
            "start_time": "2026-05-08T00:00:00+00:00",
            "end_time": "2026-05-09T00:00:00+00:00",
            "tenant_id": "tenant-a",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total_rules"] == 3
    assert payload["active_rules"] == 2
    assert payload["mapped_rules"] == 2
    assert payload["unmapped_rules"] == 1
    assert payload["techniques_covered"] == 2
    assert payload["total_alerts"] == 1
    assert payload["alerting_rules"] == 1
    assert payload["silent_active_rules"] == 1
    assert payload["top_techniques"][0]["technique_id"] in {"T1059.001", "T1071.004"}
    assert payload["noisy_rules"][0]["rule_id"] == execution_rule["id"]
    assert payload["silent_rules"][0]["title"] == "Suspicious PowerShell Execution"


async def test_analyst_can_acknowledge_and_close_alert(
    detection_context: DetectionApiContext,
) -> None:
    body = await _import_rule(detection_context, EXECUTION_RULE, status="active")
    await detection_context.client.post(
        f"/api/v1/detections/rules/{body['id']}/execute",
        headers={"Authorization": f"Bearer {detection_context.engineer_token}"},
        json={
            "start_time": "2026-05-08T00:00:00+00:00",
            "end_time": "2026-05-09T00:00:00+00:00",
            "tenant_id": "tenant-a",
        },
    )
    alert_id = detection_context.alert_repository.alerts[0].id

    acknowledged = await detection_context.client.patch(
        f"/api/v1/detections/alerts/{alert_id}",
        headers={"Authorization": f"Bearer {detection_context.analyst_token}"},
        json={"status": "acknowledged", "investigation_note": "Review started"},
    )
    closed = await detection_context.client.patch(
        f"/api/v1/detections/alerts/{alert_id}",
        headers={"Authorization": f"Bearer {detection_context.analyst_token}"},
        json={
            "status": "closed",
            "disposition": "true_positive",
            "investigation_note": "Confirmed suspicious execution",
        },
    )

    assert acknowledged.status_code == 200
    assert acknowledged.json()["status"] == "acknowledged"
    assert acknowledged.json()["assigned_to"] is not None
    assert closed.status_code == 200
    assert closed.json()["status"] == "closed"
    assert closed.json()["disposition"] == "true_positive"
    assert closed.json()["closed_at"] is not None


async def test_viewer_cannot_update_alert_workflow(
    detection_context: DetectionApiContext,
) -> None:
    body = await _import_rule(detection_context, EXECUTION_RULE, status="active")
    await detection_context.client.post(
        f"/api/v1/detections/rules/{body['id']}/execute",
        headers={"Authorization": f"Bearer {detection_context.engineer_token}"},
        json={
            "start_time": "2026-05-08T00:00:00+00:00",
            "end_time": "2026-05-09T00:00:00+00:00",
            "tenant_id": "tenant-a",
        },
    )
    alert_id = detection_context.alert_repository.alerts[0].id

    response = await detection_context.client.patch(
        f"/api/v1/detections/alerts/{alert_id}",
        headers={"Authorization": f"Bearer {detection_context.viewer_token}"},
        json={"status": "acknowledged"},
    )

    assert response.status_code == 403


async def test_closed_alert_cannot_be_reopened(
    detection_context: DetectionApiContext,
) -> None:
    body = await _import_rule(detection_context, EXECUTION_RULE, status="active")
    await detection_context.client.post(
        f"/api/v1/detections/rules/{body['id']}/execute",
        headers={"Authorization": f"Bearer {detection_context.engineer_token}"},
        json={
            "start_time": "2026-05-08T00:00:00+00:00",
            "end_time": "2026-05-09T00:00:00+00:00",
            "tenant_id": "tenant-a",
        },
    )
    alert_id = detection_context.alert_repository.alerts[0].id
    await detection_context.client.patch(
        f"/api/v1/detections/alerts/{alert_id}",
        headers={"Authorization": f"Bearer {detection_context.analyst_token}"},
        json={"status": "closed"},
    )

    response = await detection_context.client.patch(
        f"/api/v1/detections/alerts/{alert_id}",
        headers={"Authorization": f"Bearer {detection_context.analyst_token}"},
        json={"status": "open"},
    )

    assert response.status_code == 409


async def test_cross_tenant_rule_execution_is_rejected(
    detection_context: DetectionApiContext,
) -> None:
    body = await _import_rule(detection_context, EXECUTION_RULE, status="active")

    response = await detection_context.client.post(
        f"/api/v1/detections/rules/{body['id']}/execute",
        headers={"Authorization": f"Bearer {detection_context.engineer_token}"},
        json={
            "start_time": "2026-05-08T00:00:00+00:00",
            "end_time": "2026-05-09T00:00:00+00:00",
            "tenant_id": "tenant-b",
        },
    )

    assert response.status_code == 403
