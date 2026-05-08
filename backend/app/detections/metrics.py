"""Prometheus metrics for Detection Engineering workflows."""

from prometheus_client import Counter

detection_rule_imports_total = Counter(
    "helix_detection_rule_imports_total",
    "Total detection rules imported.",
    ("status", "severity"),
)

detection_rule_parse_failures_total = Counter(
    "helix_detection_rule_parse_failures_total",
    "Total Sigma rule parsing failures.",
    ("reason",),
)

detection_rule_api_requests_total = Counter(
    "helix_detection_rule_api_requests_total",
    "Total Detection Engineering API requests.",
    ("endpoint",),
)

detection_rule_executions_total = Counter(
    "helix_detection_rule_executions_total",
    "Total bounded detection rule executions.",
    ("rule_status", "matched"),
)

detection_alerts_created_total = Counter(
    "helix_detection_alerts_created_total",
    "Total persisted detection alerts created from rule execution.",
    ("severity", "status"),
)
