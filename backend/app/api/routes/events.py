"""Security event ingestion API routes."""

import json
from typing import cast

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
    resolve_tenant_scope_for_request,
)
from app.events.metrics import events_ingested_total, events_rejected_total
from app.events.normalizer import EventNormalizer
from app.events.repositories import EventRepository
from app.events.schemas import EventIngestRequest, EventIngestResponse
from app.events.service import EventIngestionService
from app.users.schemas import Principal

router = APIRouter(prefix="/events", tags=["events"])

MAX_INGEST_BODY_BYTES = 256 * 1024


@router.post("/ingest", response_model=EventIngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(request: Request) -> EventIngestResponse | JSONResponse:
    """Receive, validate, normalize, and store a single JSON security event."""
    correlation_id = getattr(request.state, "correlation_id", None) or "unknown"
    principal = await resolve_current_user_from_request(request)
    await ensure_permissions_for_request(request, principal, {Permission.EVENTS_INGEST.value})

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_INGEST_BODY_BYTES:
            await _audit_rejection(request, principal, correlation_id, "payload_too_large")
            events_rejected_total.labels(reason="payload_too_large").inc()
            return JSONResponse(status_code=413, content={"detail": "Payload too large"})
        body.extend(chunk)

    try:
        decoded = json.loads(body)
    except (ValueError, RecursionError):
        await _audit_rejection(request, principal, correlation_id, "malformed_json")
        events_rejected_total.labels(reason="malformed_json").inc()
        return JSONResponse(status_code=400, content={"detail": "Malformed JSON payload"})

    try:
        payload = EventIngestRequest.model_validate(decoded)
    except ValidationError as exc:
        await _audit_rejection(request, principal, correlation_id, "schema_validation_failed")
        events_rejected_total.labels(reason="schema_validation_failed").inc()
        details = exc.errors(include_input=False, include_context=False)
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(details)})

    target = payload.tenant_id if "tenant_id" in payload.model_fields_set else principal.tenant_id
    await resolve_tenant_scope_for_request(request, principal, target)
    payload = payload.model_copy(update={"tenant_id": target})
    service = EventIngestionService(
        repository=_get_event_repository(request),
        normalizer=EventNormalizer(),
        audit=AuditService(request.app.state.audit_repository),
    )
    response = await service.ingest(payload, correlation_id=correlation_id, actor_id=principal.id)
    events_ingested_total.labels(
        category=response.category.value,
        severity=response.severity.value,
    ).inc()
    return response


def _get_event_repository(request: Request) -> EventRepository:
    return cast(EventRepository, request.app.state.event_repository)


async def _audit_rejection(
    request: Request, principal: Principal, correlation_id: str, reason: str,
) -> None:
    await AuditService(request.app.state.audit_repository).record(
        AuditAction.EVENT_VALIDATION_FAILED,
        "failure",
        correlation_id=correlation_id,
        actor_id=principal.id,
        metadata={"reason": reason, "tenant_id": principal.tenant_id},
    )
