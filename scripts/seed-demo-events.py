#!/usr/bin/env python3
"""Seed deterministic synthetic events for local demo walkthroughs."""

from __future__ import annotations

import http.client
import json
import os
import sys
from typing import Any
from urllib.parse import urlparse

API_BASE_URL = os.environ.get(
    "HELIX_API_BASE_URL",
    "http://localhost:8000/api/v1",
).rstrip("/")
TENANT_ID = os.environ.get("HELIX_DEMO_TENANT_ID", "default")


EVENTS: list[dict[str, Any]] = [
    {
        "source": {"name": "edr", "product": "endpoint", "vendor": "Helix Demo"},
        "tenant_id": TENANT_ID,
        "severity": "high",
        "category": "endpoint",
        "payload": {
            "event": {"action": "process started"},
            "process": {
                "name": "powershell.exe",
                "command_line": "powershell -enc demo",
            },
            "host": {"name": "workstation-07", "ip": "10.20.30.40"},
            "user": {"name": "analyst.demo"},
        },
    },
    {
        "source": {"name": "identity", "product": "sso", "vendor": "Helix Demo"},
        "tenant_id": TENANT_ID,
        "severity": "medium",
        "category": "authentication",
        "payload": {
            "event": {"action": "login failed"},
            "user": {
                "name": "analyst.demo",
                "email": "analyst.demo@example.test",
            },
            "source": {"ip": "203.0.113.25"},
        },
    },
    {
        "source": {"name": "firewall", "product": "network", "vendor": "Helix Demo"},
        "tenant_id": TENANT_ID,
        "severity": "critical",
        "category": "network",
        "payload": {
            "event": {"action": "connection blocked"},
            "src_ip": "10.20.30.40",
            "dest_ip": "198.51.100.10",
            "ioc": {"domain": "malicious-demo.example"},
        },
    },
]


def main() -> int:
    endpoint = _validated_endpoint(f"{API_BASE_URL}/events/ingest")
    token = os.environ.get("HELIX_API_TOKEN", "").strip()
    if not token:
        print("Set HELIX_API_TOKEN to a local ingestion account's access token.", file=sys.stderr)
        return 1
    print(f"Seeding {len(EVENTS)} synthetic demo events into {endpoint}")

    for event in EVENTS:
        response = _post_event(endpoint, event, token)
        event_id = response.get("normalized_event_id", "unknown")
        print(f"- {event['source']['name']} {event['category']} accepted as {event_id}")

    print("Demo event seed complete.")
    return 0


def _post_event(endpoint: str, event: dict[str, Any], token: str) -> dict[str, Any]:
    parsed = urlparse(endpoint)
    assert parsed.hostname is not None  # validated before sending credentials
    connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else (
        http.client.HTTPConnection
    )
    connection = connection_type(parsed.hostname, port=parsed.port, timeout=10)
    body = json.dumps(event).encode("utf-8")
    try:
        connection.request(
            "POST", parsed.path, body,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        response = connection.getresponse()
        if response.status != 202:
            print(f"Event ingestion failed with HTTP {response.status}.", file=sys.stderr)
            raise SystemExit(1)
        return json.loads(response.read().decode("utf-8"))
    except (OSError, http.client.HTTPException) as exc:
        print("Cannot reach the configured local Helix Sentinel API.", file=sys.stderr)
        raise SystemExit(1) from exc
    finally:
        connection.close()


def _validated_endpoint(endpoint: str) -> str:
    parsed = urlparse(endpoint)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query or parsed.fragment
    ):
        print(
            "HELIX_API_BASE_URL must be a loopback HTTP(S) URL with no credentials or query.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return endpoint


if __name__ == "__main__":
    raise SystemExit(main())
