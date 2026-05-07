"""Prometheus-compatible metrics endpoint."""

from fastapi import APIRouter, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

metrics_router = APIRouter()


@metrics_router.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    """Expose process metrics for Prometheus scraping."""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

