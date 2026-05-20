#!/usr/bin/env python3
"""Seed deterministic synthetic events for local demo walkthroughs."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any


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
    endpoint = f"{API_BASE_URL}/events/ingest"
    print(f"Seeding {len(EVENTS)} synthetic demo events into {endpoint}")

    for event in EVENTS:
        response = _post_event(endpoint, event)
        event_id = response.get("event_id", "unknown")
        print(f"- {event['source']['name']} {event['category']} accepted as {event_id}")

    print("Demo event seed complete.")
    return 0


def _post_event(endpoint: str, event: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(event).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(f"Event ingestion failed with HTTP {exc.code}: {detail}", file=sys.stderr)
        raise SystemExit(1) from exc
    except urllib.error.URLError as exc:
        print(
            f"Cannot reach Helix Sentinel API at {endpoint}: {exc.reason}",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc


if __name__ == "__main__":
    raise SystemExit(main())
