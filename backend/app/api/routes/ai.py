"""AI-assisted security analytics API routes."""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.ai.metrics import ai_analytics_requests_total
from app.ai.repositories import InMemoryAIEventRepository
from app.ai.schemas import (
    AIAnalyticsFilter,
    AIAnalyticsSummary,
    AnomalyListResponse,
    EnrichmentListResponse,
)
from app.ai.service import AIAnalyticsService
from app.auth.rbac import Permission
from app.core.dependencies.security import (
    ensure_permissions_for_request,
    resolve_current_user_from_request,
    resolve_tenant_scope_for_request,
)
from app.events.repositories import InMemoryEventRepository

router = APIRouter(prefix="/ai", tags=["ai"])


@router.get("/anomalies", response_model=AnomalyListResponse)
async def list_anomalies(request: Request) -> AnomalyListResponse | JSONResponse:
    """Return explainable deterministic anomaly findings."""
    prepared = await _prepare_request(request, "anomalies")
    if isinstance(prepared, JSONResponse):
        return prepared
    filters, service = prepared
    correlation_id = getattr(request.state, "correlation_id", None)
    return await service.anomalies(filters, correlation_id=correlation_id)


@router.get("/enrichments", response_model=EnrichmentListResponse)
async def list_enrichments(request: Request) -> EnrichmentListResponse | JSONResponse:
    """Return deterministic NLP/classification enrichment metadata."""
    prepared = await _prepare_request(request, "enrichments")
    if isinstance(prepared, JSONResponse):
        return prepared
    filters, service = prepared
    return await service.enrichments(filters)


@router.get("/summary", response_model=AIAnalyticsSummary)
async def ai_summary(request: Request) -> AIAnalyticsSummary | JSONResponse:
    """Return dashboard-ready AI-assisted analytics summary."""
    prepared = await _prepare_request(request, "summary")
    if isinstance(prepared, JSONResponse):
        return prepared
    filters, service = prepared
    return await service.summary(filters)


async def _prepare_request(
    request: Request,
    endpoint: str,
) -> tuple[AIAnalyticsFilter, AIAnalyticsService] | JSONResponse:
    principal = await resolve_current_user_from_request(request)
    await ensure_permissions_for_request(request, principal, {Permission.ANALYTICS_READ.value})
    ai_analytics_requests_total.labels(endpoint=endpoint).inc()
    try:
        filters = AIAnalyticsFilter.model_validate(_query_params(request))
    except (ValidationError, ValueError) as exc:
        detail = exc.errors() if isinstance(exc, ValidationError) else str(exc)
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(detail)})
    tenant_id = await resolve_tenant_scope_for_request(request, principal, filters.tenant_id)
    filters = filters.model_copy(update={"tenant_id": tenant_id})
    return filters, AIAnalyticsService(await _repository(request))


async def _repository(request: Request) -> InMemoryAIEventRepository:
    event_repository = request.app.state.event_repository
    if isinstance(event_repository, InMemoryEventRepository):
        return InMemoryAIEventRepository(event_repository.normalized_events)
    events = await event_repository.list_normalized_events()
    return InMemoryAIEventRepository(events)


def _query_params(request: Request) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for key, value in request.query_params.multi_items():
        if key in {"start_time", "end_time"}:
            values[key] = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            values[key] = value
    return values
