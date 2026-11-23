"""Replay one synthetic investigation against the migrated, disposable CI database."""

import json
import os
import secrets
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.security.passwords import hash_password
from app.users.models import Role, User, UserRole
from helix_sentinel.core.config import Settings
from helix_sentinel.main import create_app


@pytest.mark.skipif(os.getenv("HELIX_RUN_DATABASE_DEMO") != "1", reason="isolated PostgreSQL demo")
async def test_synthetic_investigation(test_settings: Settings) -> None:
    """Exercise the authoritative routers and PostgreSQL adapters with a single local account."""
    app = create_app(test_settings)
    account_id = uuid4()
    password = secrets.token_urlsafe(32)
    email = f"demo-{account_id.hex}@example.test"
    async with app.state.db_session_factory() as session, session.begin():
        role = await session.scalar(select(Role).where(Role.name == "engineer"))
        if role is None:
            role = Role(name="engineer")
            session.add(role)
            await session.flush()
        session.add(User(
            id=account_id, email=email, display_name="Demo", password_hash=hash_password(password),
        ))
        await session.flush()
        session.add(UserRole(user_id=account_id, role_id=role.id))

    source = f"identity-{account_id.hex}"
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver/api/v1/",
    ) as client:
        login = await client.post("auth/login", json={"email": email, "password": password})
        assert login.status_code == 200
        client.headers["Authorization"] = f"Bearer {login.json()['access_token']}"
        event = await client.post("events/ingest", json={
            "source": {"name": source}, "category": "authentication",
            "payload": {"event": {"action": "synthetic login review"}},
        })
        assert event.status_code == 202
        event_id = event.json()["normalized_event_id"]
        rule = await client.post("detections/rules/sigma", json={
            "status": "active",
            "content": (
                "title: Synthetic identity review\nlevel: medium\n"
                "logsource:\n  category: authentication\n"
                f"detection:\n  selection:\n    source: {source}\n  condition: selection\n"
            ),
        })
        assert rule.status_code == 201
        rule_id = rule.json()["id"]
        execution = await client.post(
            f"detections/rules/{rule_id}/execute", json={"source": source, "limit": 5},
        )
        assert execution.status_code == 200
        result = execution.json()
        assert result["evaluated_events"] == result["matched_events"] == 1
        assert result["matches"][0]["event_id"] == event_id

        queue = await client.get("detections/alerts", params={"rule_id": rule_id})
        assert queue.status_code == 200 and queue.json()["total"] == 1
        alert = queue.json()["items"][0]
        assert alert["event_id"] == event_id and alert["status"] == "open"
        alert_path = f"detections/alerts/{alert['id']}"
        detail = await client.get(alert_path)
        assert detail.status_code == 200 and detail.json()["rule_id"] == rule_id
        acknowledged = await client.patch(alert_path, json={"status": "acknowledged"})
        assert acknowledged.status_code == 200 and acknowledged.json()["acknowledged_at"]
        closed = await client.patch(alert_path, json={
            "status": "closed", "disposition": "false_positive",
            "investigation_note": "Synthetic fixture reviewed.",
        })
        assert closed.status_code == 200 and closed.json()["closed_at"]
        reread = await client.get(alert_path)
        assert reread.status_code == 200 and reread.json()["status"] == "closed"
        audit = await client.get("analytics/security-activity", params={"limit": 50})
        assert audit.status_code == 200
        changes = [
            row for row in audit.json()["recent_activity"]
            if row["resource"] == alert["id"] and row["action"] == "detections.alert_updated"
        ]
        assert len(changes) == 2 and all(row["outcome"] == "success" for row in changes)
        print(json.dumps({
            "source": source, "event_id": event_id, "rule_id": rule_id, "alert_id": alert["id"],
            "evaluated": result["evaluated_events"], "matched": result["matched_events"],
            "observed_states": [
                alert["status"], acknowledged.json()["status"], reread.json()["status"],
            ],
            "audited_alert_updates": len(changes),
        }))

