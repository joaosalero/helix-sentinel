"""Security event normalization logic."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from app.events.schemas import (
    EventIngestRequest,
    NormalizedActor,
    NormalizedAsset,
    NormalizedEvent,
)
from app.events.taxonomy import EventCategory, EventSeverity

NORMALIZATION_VERSION = "v1"


class EventNormalizer:
    """Convert heterogeneous security telemetry into a query-friendly shape."""

    def normalize(self, request: EventIngestRequest, raw_event_id: UUID) -> NormalizedEvent:
        """Normalize an ingestion request using explicit, conservative heuristics."""
        payload = request.payload
        category = request.category or infer_category(payload)
        severity = request.severity or infer_severity(payload)
        event_time = request.event_time or datetime.now(UTC)
        title = (
            _first_string(payload, ("event.action", "action", "message", "event_type"))
            or category.value
        )

        return NormalizedEvent(
            id=uuid4(),
            raw_event_id=raw_event_id,
            tenant_id=request.tenant_id,
            source_name=request.source.name,
            source_product=request.source.product,
            source_vendor=request.source.vendor,
            category=category,
            severity=severity,
            event_time=event_time,
            ingested_at=datetime.now(UTC),
            title=title[:240],
            actor=NormalizedActor(
                user_id=_first_string(payload, ("user.id", "actor.id", "user_id")),
                username=_first_string(payload, ("user.name", "username", "actor.name")),
                email=_first_string(payload, ("user.email", "email", "actor.email")),
                ip_address=_first_string(payload, ("source.ip", "src_ip", "client.ip")),
            ),
            asset=NormalizedAsset(
                asset_id=_first_string(payload, ("host.id", "asset.id", "device.id")),
                hostname=_first_string(payload, ("host.name", "hostname", "device.hostname")),
                ip_address=_first_string(payload, ("destination.ip", "dest_ip", "host.ip")),
            ),
            network=_network_metadata(payload),
            ioc=_ioc_metadata(payload),
            enrichment={"status": "pending"},
            normalization_version=NORMALIZATION_VERSION,
        )


def infer_category(payload: dict[str, Any]) -> EventCategory:
    """Infer a high-level event category from common telemetry fields."""
    text = " ".join(str(value).lower() for value in _flatten_values(payload))
    if any(term in text for term in ("login", "logon", "authentication", "password")):
        return EventCategory.AUTHENTICATION
    if any(term in text for term in ("permission", "authorization", "denied", "forbidden")):
        return EventCategory.AUTHORIZATION
    if any(term in text for term in ("src_ip", "dest_ip", "network", "dns", "http", "firewall")):
        return EventCategory.NETWORK
    if any(term in text for term in ("process", "endpoint", "host", "edr", "file")):
        return EventCategory.ENDPOINT
    if any(term in text for term in ("ioc", "indicator", "hash", "domain", "malware")):
        return EventCategory.IOC
    if any(term in text for term in ("audit", "configuration", "policy")):
        return EventCategory.AUDIT
    if any(term in text for term in ("service", "system", "health")):
        return EventCategory.SYSTEM
    return EventCategory.GENERIC


def infer_severity(payload: dict[str, Any]) -> EventSeverity:
    """Normalize common severity values into the platform scale."""
    raw = _first_string(payload, ("severity", "event.severity", "level", "risk")) or "info"
    value = raw.lower()
    if value in {"critical", "crit", "fatal", "5"}:
        return EventSeverity.CRITICAL
    if value in {"high", "error", "4"}:
        return EventSeverity.HIGH
    if value in {"medium", "warning", "warn", "3"}:
        return EventSeverity.MEDIUM
    if value in {"low", "notice", "2"}:
        return EventSeverity.LOW
    return EventSeverity.INFO


def _first_string(payload: dict[str, Any], paths: tuple[str, ...]) -> str | None:
    for path in paths:
        value = _get_path(payload, path)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, int | float):
            return str(value)
    return None


def _get_path(payload: dict[str, Any], path: str) -> Any:
    current: Any = payload
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _network_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in {
            "source_ip": _first_string(payload, ("source.ip", "src_ip", "client.ip")),
            "destination_ip": _first_string(payload, ("destination.ip", "dest_ip", "server.ip")),
            "protocol": _first_string(payload, ("network.protocol", "protocol")),
        }.items()
        if value is not None
    }


def _ioc_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in {
            "indicator": _first_string(payload, ("ioc.value", "indicator", "threat.indicator")),
            "indicator_type": _first_string(payload, ("ioc.type", "indicator_type")),
            "file_hash": _first_string(payload, ("file.hash", "hash", "sha256")),
        }.items()
        if value is not None
    }


def _flatten_values(value: Any) -> list[Any]:
    if isinstance(value, dict):
        values: list[Any] = []
        for key, nested in value.items():
            values.append(key)
            values.extend(_flatten_values(nested))
        return values
    if isinstance(value, list):
        values = []
        for nested in value:
            values.extend(_flatten_values(nested))
        return values
    return [value]
