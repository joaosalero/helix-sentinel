"""IOC repository adapter tests."""

from datetime import UTC, datetime
from uuid import uuid4

from app.enrichment.repositories import (
    PostgresIOCRepository,
    _ioc_record_from_request,
    _to_ioc_model,
    _to_ioc_record,
    _to_match_values,
)
from app.enrichment.schemas import ConfidenceFactor, EventIOCMatch, IOCCreateRequest
from app.enrichment.taxonomy import EnrichmentStatus
from helix_sentinel.core.config import Settings
from helix_sentinel.main import create_app


def test_authoritative_runtime_uses_postgres_ioc_repository() -> None:
    app = create_app(
        Settings(
            environment="test",
            secret_key="test-secret-key-with-at-least-32-bytes",
            database_url="postgresql+asyncpg://helix:helix@localhost:5432/helix_sentinel_test",
        )
    )

    assert isinstance(app.state.ioc_repository, PostgresIOCRepository)


def test_ioc_repository_round_trips_ioc_shape() -> None:
    now = datetime.now(UTC)
    request = IOCCreateRequest.model_validate(
        {
            "indicator_type": "domain",
            "value": "Example.COM",
            "confidence": 80,
            "severity": "high",
            "source_name": "internal-ti",
            "source_reliability": "verified",
            "tags": ["Phishing", "phishing"],
            "metadata": {"campaign": "spring"},
        }
    )

    record = _ioc_record_from_request(request, now=now)
    model = _to_ioc_model(record)
    restored = _to_ioc_record(model)

    assert restored.id == record.id
    assert restored.indicator_type.value == "domain"
    assert restored.value == "example.com"
    assert restored.confidence == 80
    assert restored.severity.value == "high"
    assert restored.source_reliability.value == "verified"
    assert restored.tags == ["phishing"]
    assert restored.metadata == {"campaign": "spring"}


def test_ioc_repository_maps_match_values_without_losing_context() -> None:
    event_id = uuid4()
    ioc_id = uuid4()
    match = EventIOCMatch(
        event_id=event_id,
        ioc_id=ioc_id,
        indicator_type="ip",
        value="8.8.8.8",
        status=EnrichmentStatus.MATCHED,
        confidence=75,
        confidence_factors=[
            ConfidenceFactor(name="source", points=20, reason="Verified source")
        ],
        matched_fields=["network.source_ip"],
        metadata={"tenant_id": "default"},
    )

    values = _to_match_values(match)

    assert values["event_id"] == event_id
    assert values["ioc_id"] == ioc_id
    assert values["status"] == "matched"
    assert values["confidence"] == 75
    assert values["matched_fields"] == ["network.source_ip"]
    assert values["metadata"] == {"tenant_id": "default"}
