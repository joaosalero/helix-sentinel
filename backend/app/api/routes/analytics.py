"""SOC analytics API routes."""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.analytics.metrics import analytics_requests_total
from app.analytics.repositories import InMemoryAnalyticsRepository
from app.analytics.schemas import (
    AnalyticsFilter,
    CountSummary,
    SocOverview,
    SourceMetric,
    TrendPoint,
)
from app.analytics.service import SocAnalyticsService
from app.auth.rbac import Permission
from app.core.dependencies.security import (
    ensure_permissions_for_request,
    resolve_current_user_from_request,
)
from app.events.repositories import InMemoryEventRepository

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/overview", response_model=SocOverview)
async def overview(request: Request) -> SocOverview | JSONResponse:
    """Return dashboard-ready SOC operational metrics."""
    parsed = await _prepare_analytics_request(request, "overview")
    if isinstance(parsed, JSONResponse):
        return parsed
    filters, service = parsed
    correlation_id = getattr(request.state, "correlation_id", None)
    return await service.overview(filters, correlation_id=correlation_id)


@router.get("/severity", response_model=list[CountSummary])
async def severity_summary(request: Request) -> list[CountSummary] | JSONResponse:
    """Return severity distribution for a validated time range."""
    parsed = await _prepare_analytics_request(request, "severity")
    if isinstance(parsed, JSONResponse):
        return parsed
    filters, service = parsed
    return await service.repository.severity_distribution(filters)


@router.get("/categories", response_model=list[CountSummary])
async def category_summary(request: Request) -> list[CountSummary] | JSONResponse:
    """Return category distribution for a validated time range."""
    parsed = await _prepare_analytics_request(request, "categories")
    if isinstance(parsed, JSONResponse):
        return parsed
    filters, service = parsed
    return await service.repository.category_distribution(filters)


@router.get("/trends", response_model=list[TrendPoint])
async def trend_summary(request: Request) -> list[TrendPoint] | JSONResponse:
    """Return event volume trend buckets."""
    parsed = await _prepare_analytics_request(request, "trends")
    if isinstance(parsed, JSONResponse):
        return parsed
    filters, service = parsed
    return await service.repository.trend(filters)


@router.get("/sources", response_model=list[SourceMetric])
async def source_summary(request: Request) -> list[SourceMetric] | JSONResponse:
    """Return paginated source metrics."""
    parsed = await _prepare_analytics_request(request, "sources")
    if isinstance(parsed, JSONResponse):
        return parsed
    filters, service = parsed
    return await service.repository.source_metrics(filters)


async def _prepare_analytics_request(
    request: Request,
    endpoint: str,
) -> tuple[AnalyticsFilter, SocAnalyticsService] | JSONResponse:
    principal = await resolve_current_user_from_request(request)
    await ensure_permissions_for_request(request, principal, {Permission.ANALYTICS_READ.value})
    analytics_requests_total.labels(endpoint=endpoint).inc()
    try:
        filters = AnalyticsFilter.model_validate(_query_params(request))
    except (ValidationError, ValueError) as exc:
        detail = exc.errors() if isinstance(exc, ValidationError) else str(exc)
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(detail)})
    return filters, SocAnalyticsService(await _analytics_repository(request))


async def _analytics_repository(request: Request) -> InMemoryAnalyticsRepository:
    event_repository = request.app.state.event_repository
    if isinstance(event_repository, InMemoryEventRepository):
        return InMemoryAnalyticsRepository(event_repository.normalized_events)
    events = await event_repository.list_normalized_events()
    return InMemoryAnalyticsRepository(events)


def _query_params(request: Request) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for key, value in request.query_params.multi_items():
        if key in {"start_time", "end_time"}:
            values[key] = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            values[key] = value
    return values
