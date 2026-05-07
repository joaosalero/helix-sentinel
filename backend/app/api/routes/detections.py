"""Detection Engineering API routes."""

from typing import cast
from uuid import UUID

from fastapi import APIRouter, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.audit.events import AuditAction
from app.audit.service import AuditService
from app.auth.rbac import Permission
from app.core.dependencies.security import (
    ensure_permissions_for_request,
    resolve_current_user_from_request,
)
from app.detections.metrics import (
    detection_rule_api_requests_total,
    detection_rule_parse_failures_total,
)
from app.detections.parser import SigmaParseError, SigmaParser
from app.detections.repositories import DetectionRuleRepository
from app.detections.schemas import (
    DetectionRule,
    DetectionRuleListFilters,
    DetectionRuleListResponse,
    SigmaRuleImportRequest,
)
from app.detections.service import DetectionRuleService

router = APIRouter(prefix="/detections", tags=["detections"])


@router.post("/rules/sigma", response_model=DetectionRule, status_code=status.HTTP_201_CREATED)
async def import_sigma_rule(request: Request) -> DetectionRule | JSONResponse:
    """Validate and import a Sigma rule into the detection catalog."""
    principal = await resolve_current_user_from_request(request)
    await ensure_permissions_for_request(request, principal, {Permission.DETECTIONS_WRITE.value})
    detection_rule_api_requests_total.labels(endpoint="import_sigma").inc()
    correlation_id = getattr(request.state, "correlation_id", None)

    try:
        payload = SigmaRuleImportRequest.model_validate(await request.json())
    except ValidationError as exc:
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(exc.errors())})

    service = _service(request)
    try:
        return await service.import_sigma(payload, correlation_id=correlation_id)
    except SigmaParseError as exc:
        detection_rule_parse_failures_total.labels(reason="invalid_sigma").inc()
        await AuditService(request.app.state.audit_repository).record(
            AuditAction.DETECTION_RULE_PARSE_FAILED,
            "failure",
            actor_id=principal.id,
            actor_email=principal.email,
            correlation_id=correlation_id,
            metadata={"reason": str(exc)},
        )
        return JSONResponse(status_code=422, content={"detail": str(exc)})


@router.get("/rules", response_model=DetectionRuleListResponse)
async def list_detection_rules(request: Request) -> DetectionRuleListResponse | JSONResponse:
    """List detection rules with safe filtering and pagination."""
    principal = await resolve_current_user_from_request(request)
    await ensure_permissions_for_request(request, principal, {Permission.DETECTIONS_READ.value})
    detection_rule_api_requests_total.labels(endpoint="list_rules").inc()
    try:
        filters = DetectionRuleListFilters.model_validate(dict(request.query_params))
    except ValidationError as exc:
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(exc.errors())})
    return await _service(request).list(filters)


@router.get("/rules/{rule_id}", response_model=DetectionRule)
async def get_detection_rule(request: Request, rule_id: UUID) -> DetectionRule | JSONResponse:
    """Return detection rule details without executing rule logic."""
    principal = await resolve_current_user_from_request(request)
    await ensure_permissions_for_request(request, principal, {Permission.DETECTIONS_READ.value})
    detection_rule_api_requests_total.labels(endpoint="get_rule").inc()
    rule = await _service(request).get(rule_id)
    if rule is None:
        return JSONResponse(status_code=404, content={"detail": "Detection rule not found"})
    return rule


def _service(request: Request) -> DetectionRuleService:
    return DetectionRuleService(
        repository=_repository(request),
        parser=SigmaParser(),
        audit=AuditService(request.app.state.audit_repository),
    )


def _repository(request: Request) -> DetectionRuleRepository:
    return cast(DetectionRuleRepository, request.app.state.detection_rule_repository)
