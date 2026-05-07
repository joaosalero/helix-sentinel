"""Detection Engineering API tests."""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.app import create_security_app
from app.auth.rbac import permissions_for_roles
from app.core.config.settings import SecuritySettings
from app.core.security.passwords import hash_password
from app.detections.repositories import InMemoryDetectionRuleRepository
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


@dataclass
class DetectionApiContext:
    """Test wiring for Detection Engineering APIs."""

    client: AsyncClient
    engineer_token: str
    viewer_token: str
    repository: InMemoryDetectionRuleRepository


@pytest.fixture
async def detection_context() -> AsyncIterator[DetectionApiContext]:
    engineer_roles = frozenset({"engineer"})
    viewer_roles = frozenset({"viewer"})
    engineer = StoredUser(
        id=uuid4(),
        email="engineer@example.com",
        display_name="Detection Engineer",
        password_hash=hash_password("valid engineer password"),
        status=UserStatus.ACTIVE,
        roles=engineer_roles,
        permissions=permissions_for_roles(engineer_roles),
    )
    viewer = StoredUser(
        id=uuid4(),
        email="viewer@example.com",
        display_name="Viewer",
        password_hash=hash_password("valid viewer password"),
        status=UserStatus.ACTIVE,
        roles=viewer_roles,
        permissions=permissions_for_roles(viewer_roles),
    )
    repository = InMemoryDetectionRuleRepository()
    app = create_security_app()
    app.state.user_repository = InMemoryUserRepository([engineer, viewer])
    app.state.detection_rule_repository = repository
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
        yield DetectionApiContext(
            client=client,
            engineer_token=engineer_login.json()["access_token"],
            viewer_token=viewer_login.json()["access_token"],
            repository=repository,
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
