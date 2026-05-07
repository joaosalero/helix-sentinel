"""Prometheus metrics for IOC enrichment."""

from prometheus_client import Counter, Histogram

ioc_api_requests_total = Counter(
    "helix_ioc_api_requests_total",
    "Total IOC enrichment API requests.",
    ("endpoint",),
)

ioc_created_total = Counter(
    "helix_ioc_created_total",
    "Total IOCs created.",
    ("indicator_type", "severity"),
)

ioc_matches_total = Counter(
    "helix_ioc_matches_total",
    "Total event-to-IOC matches.",
    ("indicator_type",),
)

ioc_enrichment_duration_seconds = Histogram(
    "helix_ioc_enrichment_duration_seconds",
    "Deterministic IOC enrichment execution latency.",
)

