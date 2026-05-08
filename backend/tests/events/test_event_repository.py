"""Event repository adapter tests."""

from uuid import uuid4

from app.events.normalizer import EventNormalizer
from app.events.repositories import (
    PostgresEventRepository,
    _raw_record_from_request,
    _to_normalized_model,
    _to_normalized_schema,
    _to_raw_model,
)
from app.events.schemas import EventIngestRequest
from helix_sentinel.core.config import Settings
from helix_sentinel.main import create_app


def test_authoritative_runtime_uses_postgres_event_repository() -> None:
    app = create_app(
        Settings(
            environment="test",
            secret_key="test-secret-key-with-at-least-32-bytes",
            database_url="postgresql+asyncpg://helix:helix@localhost:5432/helix_sentinel_test",
        )
    )

    assert isinstance(app.state.event_repository, PostgresEventRepository)


def test_event_repository_maps_raw_event_without_changing_ingestion_fields() -> None:
    request = EventIngestRequest.model_validate(
        {
            "source": {"name": "edr", "product": "endpoint", "vendor": "Acme"},
            "tenant_id": "tenant-a",
            "external_id": "event-1",
            "payload": {"event": {"action": "process started"}, "severity": "medium"},
        }
    )

    record = _raw_record_from_request(request, correlation_id="corr-event")
    model = _to_raw_model(record)

    assert model.id == record.id
    assert model.tenant_id == "tenant-a"
    assert model.source_name == "edr"
    assert model.external_id == "event-1"
    assert model.payload["severity"] == "medium"
    assert model.correlation_id == "corr-event"


def test_event_repository_round_trips_normalized_event_shape() -> None:
    request = EventIngestRequest.model_validate(
        {
            "source": {"name": "firewall", "product": "network"},
            "tenant_id": "tenant-a",
            "payload": {
                "message": "blocked connection",
                "severity": "high",
                "src_ip": "10.0.0.5",
            },
        }
    )
    normalized = EventNormalizer().normalize(request, uuid4())

    model = _to_normalized_model(normalized)
    restored = _to_normalized_schema(model)

    assert restored.id == normalized.id
    assert restored.raw_event_id == normalized.raw_event_id
    assert restored.tenant_id == "tenant-a"
    assert restored.source_name == "firewall"
    assert restored.category == normalized.category
    assert restored.severity == normalized.severity
    assert restored.network["source_ip"] == "10.0.0.5"
    assert restored.normalization_version == normalized.normalization_version
