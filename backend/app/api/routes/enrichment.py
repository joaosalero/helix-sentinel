"""IOC enrichment API routes."""

from typing import Any, cast
from uuid import UUID

from fastapi import APIRouter, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.audit.service import AuditService
from app.auth.rbac import Permission
from app.core.dependencies.security import (
    ensure_permissions_for_request,
    resolve_current_user_from_request,
)
from app.enrichment.metrics import ioc_api_requests_total
from app.enrichment.repositories import IOCRepository
from app.enrichment.schemas import (
    EnrichmentExecutionRequest,
    EnrichmentExecutionResponse,
    EnrichmentSummary,
    IOCCreateRequest,
    IOCListFilters,
    IOCListResponse,
    IOCRecord,
)
from app.enrichment.service import IOCEnrichmentService
from app.events.repositories import InMemoryEventRepository

router = APIRouter(prefix="/enrichment", tags=["enrichment"])


@router.post("/iocs", response_model=IOCRecord, status_code=status.HTTP_201_CREATED)
async def create_ioc(request: Request) -> IOCRecord | JSONResponse:
    """Create a locally managed IOC after strict syntax validation."""
    principal = await resolve_current_user_from_request(request)
    await ensure_permissions_for_request(request, principal, {Permission.DETECTIONS_WRITE.value})
    ioc_api_requests_total.labels(endpoint="create_ioc").inc()
    try:
        payload = IOCCreateRequest.model_validate(await request.json())
    except ValidationError as exc:
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(exc.errors())})
    service = await _service(request)
    return await service.create_ioc(
        payload,
        actor_id=principal.id,
        actor_email=principal.email,
        correlation_id=getattr(request.state, "correlation_id", None),
    )


@router.get("/iocs", response_model=IOCListResponse)
async def list_iocs(request: Request) -> IOCListResponse | JSONResponse:
    """List IOCs with safe filtering and bounded pagination."""
    await _require_analytics(request)
    ioc_api_requests_total.labels(endpoint="list_iocs").inc()
    try:
        filters = IOCListFilters.model_validate(_query_params(request))
    except ValidationError as exc:
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(exc.errors())})
    service = await _service(request)
    return await service.list_iocs(filters)


@router.get("/iocs/{ioc_id}", response_model=IOCRecord)
async def get_ioc(request: Request, ioc_id: UUID) -> IOCRecord | JSONResponse:
    """Return IOC details without exposing raw event payloads."""
    await _require_analytics(request)
    ioc_api_requests_total.labels(endpoint="get_ioc").inc()
    service = await _service(request)
    ioc = await service.get_ioc(ioc_id)
    if ioc is None:
        return JSONResponse(status_code=404, content={"detail": "IOC not found"})
    return ioc


@router.get("/summary", response_model=EnrichmentSummary)
async def enrichment_summary(request: Request) -> EnrichmentSummary:
    """Return dashboard-ready IOC enrichment inventory metrics."""
    await _require_analytics(request)
    ioc_api_requests_total.labels(endpoint="summary").inc()
    service = await _service(request)
    return await service.summary()


@router.post("/execute", response_model=EnrichmentExecutionResponse)
async def execute_enrichment(request: Request) -> EnrichmentExecutionResponse | JSONResponse:
    """Run deterministic IOC matching against stored normalized events."""
    principal = await resolve_current_user_from_request(request)
    await ensure_permissions_for_request(request, principal, {Permission.ANALYTICS_READ.value})
    ioc_api_requests_total.labels(endpoint="execute").inc()
    try:
        payload = EnrichmentExecutionRequest.model_validate(await request.json())
    except ValidationError as exc:
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(exc.errors())})
    service = await _service(request)
    return await service.enrich_events(
        payload,
        actor_id=principal.id,
        actor_email=principal.email,
        correlation_id=getattr(request.state, "correlation_id", None),
    )


async def _require_analytics(request: Request) -> None:
    principal = await resolve_current_user_from_request(request)
    await ensure_permissions_for_request(request, principal, {Permission.ANALYTICS_READ.value})


async def _service(request: Request) -> IOCEnrichmentService:
    event_repository = request.app.state.event_repository
    events = (
        event_repository.normalized_events
        if isinstance(event_repository, InMemoryEventRepository)
        else await event_repository.list_normalized_events()
    )
    return IOCEnrichmentService(
        _repository(request),
        events=events,
        audit=AuditService(request.app.state.audit_repository),
    )


def _repository(request: Request) -> IOCRepository:
    return cast(IOCRepository, request.app.state.ioc_repository)


def _query_params(request: Request) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for key, value in request.query_params.multi_items():
        values[key] = value
    return values
