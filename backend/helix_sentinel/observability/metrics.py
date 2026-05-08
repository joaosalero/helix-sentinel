"""Prometheus-compatible metrics endpoint."""

from fastapi import APIRouter, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

metrics_router = APIRouter()

http_requests_total = Counter(
    "helix_http_requests_total",
    "Total HTTP requests handled by the API.",
    ["method", "path", "status_code"],
)
http_request_duration_seconds = Histogram(
    "helix_http_request_duration_seconds",
    "HTTP request duration in seconds.",
    ["method", "path"],
)


@metrics_router.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    """Expose process metrics for Prometheus scraping."""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
