"""Prometheus metric primitives for event ingestion."""

from prometheus_client import Counter

events_ingested_total = Counter(
    "helix_events_ingested_total",
    "Total security events accepted by the ingestion API.",
    ("category", "severity"),
)

events_rejected_total = Counter(
    "helix_events_rejected_total",
    "Total security events rejected before ingestion.",
    ("reason",),
)

