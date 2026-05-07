"""Event normalization unit tests."""

from uuid import uuid4

from app.events.normalizer import EventNormalizer, infer_category, infer_severity
from app.events.schemas import EventIngestRequest
from app.events.taxonomy import EventCategory, EventSeverity


def test_infer_authentication_category() -> None:
    category = infer_category({"event": {"action": "user login failed"}})

    assert category == EventCategory.AUTHENTICATION


def test_infer_network_category() -> None:
    assert infer_category({"src_ip": "10.0.0.1", "dest_ip": "10.0.0.2"}) == EventCategory.NETWORK


def test_infer_severity_from_common_values() -> None:
    assert infer_severity({"severity": "critical"}) == EventSeverity.CRITICAL
    assert infer_severity({"level": "warn"}) == EventSeverity.MEDIUM


def test_normalizer_extracts_actor_asset_and_network_metadata() -> None:
    request = EventIngestRequest.model_validate(
        {
            "source": {"name": "okta", "product": "identity", "vendor": "Okta"},
            "payload": {
                "event": {"action": "user login failed"},
                "severity": "high",
                "user": {"id": "u-1", "email": "analyst@example.com"},
                "source": {"ip": "203.0.113.10"},
                "host": {"name": "workstation-7"},
            },
        }
    )

    event = EventNormalizer().normalize(request, uuid4())

    assert event.category == EventCategory.AUTHENTICATION
    assert event.severity == EventSeverity.HIGH
    assert event.actor.user_id == "u-1"
    assert event.actor.email == "analyst@example.com"
    assert event.actor.ip_address == "203.0.113.10"
    assert event.asset.hostname == "workstation-7"
    assert event.enrichment == {"status": "pending"}
