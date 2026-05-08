"""Detection repository adapter tests."""

from datetime import UTC, datetime
from uuid import uuid4

from app.detections.repositories import (
    PostgresDetectionRuleRepository,
    _to_rule_record,
    _to_rule_schema,
)
from app.detections.schemas import AttackTechnique, DetectionRule, DetectionRuleMetadata
from app.detections.taxonomy import DetectionCategory, DetectionSeverity, DetectionStatus
from helix_sentinel.core.config import Settings
from helix_sentinel.main import create_app


def test_authoritative_runtime_uses_postgres_detection_repository() -> None:
    app = create_app(
        Settings(
            environment="test",
            secret_key="test-secret-key-with-at-least-32-bytes",
            database_url="postgresql+asyncpg://helix:helix@localhost:5432/helix_sentinel_test",
        )
    )

    assert isinstance(app.state.detection_rule_repository, PostgresDetectionRuleRepository)


def test_detection_repository_round_trips_rule_shape() -> None:
    now = datetime.now(UTC)
    rule = DetectionRule(
        id=uuid4(),
        title="Suspicious PowerShell",
        description="PowerShell process with suspicious flags.",
        status=DetectionStatus.ACTIVE,
        severity=DetectionSeverity.HIGH,
        category=DetectionCategory.ENDPOINT,
        source="windows:process_creation",
        sigma_id="sigma-1",
        sigma_status="test",
        raw_rule={"title": "Suspicious PowerShell"},
        detection={"selection": {"Image": "powershell.exe"}},
        metadata=DetectionRuleMetadata(
            tags=["attack.execution", "attack.t1059.001"],
            references=["https://example.test/rule"],
            false_positives=["administration"],
            author="Helix",
            license="DRL",
            operational_notes="review weekly",
            tuning_metadata={"env": "prod"},
            quality_metadata={"coverage": "initial"},
        ),
        attack=[AttackTechnique(technique_id="T1059.001", tactic="execution")],
        created_at=now,
        updated_at=now,
    )

    record = _to_rule_record(rule)
    restored = _to_rule_schema(record)

    assert restored.id == rule.id
    assert restored.title == rule.title
    assert restored.status == DetectionStatus.ACTIVE
    assert restored.severity == DetectionSeverity.HIGH
    assert restored.category == DetectionCategory.ENDPOINT
    assert restored.metadata.tags == ["attack.execution", "attack.t1059.001"]
    assert restored.metadata.operational_notes == "review weekly"
    assert restored.attack[0].technique_id == "T1059.001"
    assert restored.detection == {"selection": {"Image": "powershell.exe"}}
