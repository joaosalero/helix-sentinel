"""Persistence model registration tests."""

from app.users.models import Base as AppBase
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


def test_active_feature_tables_use_authoritative_metadata() -> None:
    expected_tables = {
        "auth_users",
        "auth_roles",
        "auth_permissions",
        "auth_audit_events",
        "event_sources",
        "raw_security_events",
        "normalized_security_events",
        "detection_rules_v2",
        "detection_attack_mappings",
        "threat_insights",
        "threat_ioc_references",
        "ai_anomaly_findings",
        "ai_event_enrichments",
        "ioc_indicators",
        "event_ioc_matches",
    }

    assert AppBase is Base
    assert expected_tables.issubset(set(Base.metadata.tables))
