"""SOC analytics API routes."""

from datetime import UTC, datetime, timedelta
from typing import Any, cast

from fastapi import APIRouter, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.ai.repositories import InMemoryAIEventRepository, RepositoryBackedAIEventRepository
from app.ai.schemas import AIAnalyticsFilter, AIAnalyticsSummary
from app.ai.service import AIAnalyticsService
from app.analytics.metrics import analytics_requests_total
from app.analytics.repositories import (
    AnalyticsRepository,
    InMemoryAnalyticsRepository,
    PostgresAnalyticsRepository,
)
from app.analytics.schemas import (
    AnalyticsFilter,
    CountSummary,
    EventSearchFilters,
    EventSearchResponse,
    SocOverview,
    SocReport,
    SourceMetric,
    TrendPoint,
)
from app.analytics.service import SocAnalyticsService
from app.auth.rbac import Permission
from app.core.dependencies.security import (
    ensure_permissions_for_request,
    resolve_current_user_from_request,
    resolve_tenant_scope_for_request,
)
from app.detections.repositories import AlertReportingSnapshot, DetectionAlertRepository
from app.events.repositories import (
    EventRepository,
    InMemoryEventRepository,
    NormalizedEventQuery,
    PostgresEventRepository,
)
from app.threats.repositories import (
    EventRepositoryThreatEventRepository,
    InMemoryThreatEventRepository,
)
from app.threats.schemas import ThreatAnalyticsFilter, ThreatSummary
from app.threats.service import ThreatAnalyticsService

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


@router.get("/report", response_model=SocReport)
async def soc_report(request: Request) -> SocReport | JSONResponse:
    """Return executive and analyst-oriented SOC reporting aggregates."""
    parsed = await _prepare_analytics_request(request, "report")
    if isinstance(parsed, JSONResponse):
        return parsed
    filters, service = parsed
    if filters.end_time - filters.start_time > timedelta(days=90):
        return JSONResponse(
            status_code=422,
            content={"detail": "SOC report time range must not exceed 90 days"},
        )
    correlation_id = getattr(request.state, "correlation_id", None)
    alert_snapshot = await _alert_snapshot(request, filters)
    threat_summary = await _threat_summary(request, filters)
    ai_summary = await _ai_summary(request, filters)
    return await service.report(
        filters,
        alert_snapshot=alert_snapshot,
        threat_summary=threat_summary,
        ai_summary=ai_summary,
        correlation_id=correlation_id,
    )


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


@router.get("/events", response_model=EventSearchResponse)
async def search_events(request: Request) -> EventSearchResponse | JSONResponse:
    """Return bounded normalized events for analyst investigations."""
    principal = await resolve_current_user_from_request(request)
    await ensure_permissions_for_request(request, principal, {Permission.ANALYTICS_READ.value})
    analytics_requests_total.labels(endpoint="events").inc()
    try:
        filters = EventSearchFilters.model_validate(_query_params(request))
    except (ValidationError, ValueError) as exc:
        detail = exc.errors() if isinstance(exc, ValidationError) else str(exc)
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(detail)})
    tenant_id = await resolve_tenant_scope_for_request(request, principal, filters.tenant_id)
    filters = filters.model_copy(update={"tenant_id": tenant_id})
    event_repository = cast(EventRepository, request.app.state.event_repository)
    events = await event_repository.list_normalized_events(
        NormalizedEventQuery(
            start_time=filters.start_time,
            end_time=filters.end_time,
            tenant_id=filters.tenant_id,
            source=filters.source,
            source_product=filters.source_product,
            source_vendor=filters.source_vendor,
            category=filters.category,
            severity=filters.severity,
            title=filters.title,
            actor_username=filters.actor_username,
            actor_email=filters.actor_email,
            actor_ip=filters.actor_ip,
            asset_hostname=filters.asset_hostname,
            asset_ip=filters.asset_ip,
            ioc_value=filters.ioc_value,
            limit=filters.limit,
            offset=filters.offset,
            newest_first=True,
        )
    )
    return EventSearchResponse(items=events, limit=filters.limit, offset=filters.offset)


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
    tenant_id = await resolve_tenant_scope_for_request(request, principal, filters.tenant_id)
    filters = filters.model_copy(update={"tenant_id": tenant_id})
    return filters, SocAnalyticsService(await _analytics_repository(request))


async def _analytics_repository(request: Request) -> AnalyticsRepository:
    event_repository = request.app.state.event_repository
    if isinstance(event_repository, InMemoryEventRepository):
        return InMemoryAnalyticsRepository(event_repository.normalized_events)
    if isinstance(event_repository, PostgresEventRepository):
        return PostgresAnalyticsRepository(event_repository.session_factory)
    events = await event_repository.list_normalized_events()
    return InMemoryAnalyticsRepository(events)


async def _alert_snapshot(
    request: Request,
    filters: AnalyticsFilter,
) -> AlertReportingSnapshot:
    repository = getattr(request.app.state, "detection_alert_repository", None)
    if repository is None:
        return AlertReportingSnapshot()
    return await cast(DetectionAlertRepository, repository).reporting_snapshot(
        tenant_id=filters.tenant_id,
        start_time=filters.start_time,
        end_time=filters.end_time,
        now=datetime.now(UTC),
    )


async def _threat_summary(request: Request, filters: AnalyticsFilter) -> ThreatSummary:
    event_repository = request.app.state.event_repository
    repository = (
        InMemoryThreatEventRepository(event_repository.normalized_events)
        if isinstance(event_repository, InMemoryEventRepository)
        else EventRepositoryThreatEventRepository(event_repository)
    )
    service = ThreatAnalyticsService(repository)
    return await service.summary(
        ThreatAnalyticsFilter(
            start_time=filters.start_time,
            end_time=filters.end_time,
            tenant_id=filters.tenant_id,
            limit=100,
            offset=0,
        )
    )


async def _ai_summary(request: Request, filters: AnalyticsFilter) -> AIAnalyticsSummary:
    event_repository = request.app.state.event_repository
    repository = (
        InMemoryAIEventRepository(event_repository.normalized_events)
        if isinstance(event_repository, InMemoryEventRepository)
        else RepositoryBackedAIEventRepository(event_repository)
    )
    service = AIAnalyticsService(repository)
    return await service.summary(
        AIAnalyticsFilter(
            start_time=filters.start_time,
            end_time=filters.end_time,
            tenant_id=filters.tenant_id,
            category=filters.category,
            limit=100,
            offset=0,
        )
    )


def _query_params(request: Request) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for key, value in request.query_params.multi_items():
        if key in {"start_time", "end_time"}:
            values[key] = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            values[key] = value
    return values
