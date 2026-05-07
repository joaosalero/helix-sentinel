"""Prometheus metrics for Threat Analytics operations."""

from prometheus_client import Counter, Histogram

threat_analytics_requests_total = Counter(
    "helix_threat_analytics_requests_total",
    "Total Threat Analytics API requests.",
    ("endpoint",),
)

threat_correlations_total = Counter(
    "helix_threat_correlations_total",
    "Total generated threat correlations.",
    ("insight_type",),
)

threat_correlation_duration_seconds = Histogram(
    "helix_threat_correlation_duration_seconds",
    "Threat correlation execution latency.",
    ("operation",),
)

