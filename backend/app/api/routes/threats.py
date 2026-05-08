"""Threat Analytics API routes."""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.auth.rbac import Permission
from app.core.dependencies.security import (
    ensure_permissions_for_request,
    resolve_current_user_from_request,
    resolve_tenant_scope_for_request,
)
from app.events.repositories import InMemoryEventRepository
from app.threats.metrics import threat_analytics_requests_total
from app.threats.repositories import InMemoryThreatEventRepository
from app.threats.schemas import ThreatAnalyticsFilter, ThreatInsightListResponse, ThreatSummary
from app.threats.service import ThreatAnalyticsService

router = APIRouter(prefix="/threats", tags=["threats"])


@router.get("/insights", response_model=ThreatInsightListResponse)
async def list_threat_insights(request: Request) -> ThreatInsightListResponse | JSONResponse:
    """Generate and return filtered threat insights."""
    prepared = await _prepare_request(request, "insights")
    if isinstance(prepared, JSONResponse):
        return prepared
    filters, service = prepared
    correlation_id = getattr(request.state, "correlation_id", None)
    return await service.insights(filters, correlation_id=correlation_id)


@router.get("/summary", response_model=ThreatSummary)
async def threat_summary(request: Request) -> ThreatSummary | JSONResponse:
    """Return dashboard-ready threat correlation summary metrics."""
    prepared = await _prepare_request(request, "summary")
    if isinstance(prepared, JSONResponse):
        return prepared
    filters, service = prepared
    return await service.summary(filters)


async def _prepare_request(
    request: Request,
    endpoint: str,
) -> tuple[ThreatAnalyticsFilter, ThreatAnalyticsService] | JSONResponse:
    principal = await resolve_current_user_from_request(request)
    await ensure_permissions_for_request(request, principal, {Permission.ANALYTICS_READ.value})
    threat_analytics_requests_total.labels(endpoint=endpoint).inc()
    try:
        filters = ThreatAnalyticsFilter.model_validate(_query_params(request))
    except (ValidationError, ValueError) as exc:
        detail = exc.errors() if isinstance(exc, ValidationError) else str(exc)
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(detail)})
    tenant_id = await resolve_tenant_scope_for_request(request, principal, filters.tenant_id)
    filters = filters.model_copy(update={"tenant_id": tenant_id})
    return filters, ThreatAnalyticsService(await _repository(request))


async def _repository(request: Request) -> InMemoryThreatEventRepository:
    event_repository = request.app.state.event_repository
    if isinstance(event_repository, InMemoryEventRepository):
        return InMemoryThreatEventRepository(event_repository.normalized_events)
    events = await event_repository.list_normalized_events()
    return InMemoryThreatEventRepository(events)


def _query_params(request: Request) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for key, value in request.query_params.multi_items():
        if key in {"start_time", "end_time"}:
            values[key] = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            values[key] = value
    return values
