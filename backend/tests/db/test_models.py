"""Persistence model registration tests."""

from helix_sentinel.db.models import Base


def test_domain_tables_are_registered() -> None:
    expected_tables = {
        "identity_users",
        "identity_roles",
        "audit_events",
        "security_events",
        "detection_rules",
        "analytics_pipelines",
        "ai_enrichments",
        "threat_indicators",
        "validation_runs",
    }

    assert expected_tables.issubset(set(Base.metadata.tables))

