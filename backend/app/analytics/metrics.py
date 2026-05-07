"""Prometheus metrics for analytics API usage and latency."""

from prometheus_client import Counter, Histogram

analytics_requests_total = Counter(
    "helix_analytics_requests_total",
    "Total analytics API requests.",
    ("endpoint",),
)

analytics_query_duration_seconds = Histogram(
    "helix_analytics_query_duration_seconds",
    "Analytics aggregation latency.",
    ("operation",),
)

