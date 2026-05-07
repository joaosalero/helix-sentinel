"""Prometheus metrics for AI-assisted analytics."""

from prometheus_client import Counter, Histogram

ai_analytics_requests_total = Counter(
    "helix_ai_analytics_requests_total",
    "Total AI-assisted analytics API requests.",
    ("endpoint",),
)

ai_anomalies_generated_total = Counter(
    "helix_ai_anomalies_generated_total",
    "Total deterministic anomaly findings generated.",
    ("anomaly_type",),
)

ai_scoring_duration_seconds = Histogram(
    "helix_ai_scoring_duration_seconds",
    "AI-assisted deterministic scoring latency.",
    ("operation",),
)

