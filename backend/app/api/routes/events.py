"""Security event ingestion API routes."""

import json
from typing import cast

from fastapi import APIRouter, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.audit.events import AuditAction
from app.audit.service import AuditService
from app.events.metrics import events_ingested_total, events_rejected_total
from app.events.normalizer import EventNormalizer
from app.events.repositories import EventRepository
from app.events.schemas import EventIngestRequest, EventIngestResponse
from app.events.service import EventIngestionService

router = APIRouter(prefix="/events", tags=["events"])

MAX_INGEST_BODY_BYTES = 256 * 1024


@router.post("/ingest", response_model=EventIngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(request: Request) -> EventIngestResponse | JSONResponse:
    """Receive, validate, normalize, and store a single JSON security event."""
    correlation_id = getattr(request.state, "correlation_id", None) or "unknown"
    body = await request.body()
    if len(body) > MAX_INGEST_BODY_BYTES:
        await _audit_rejection(request, correlation_id, "payload_too_large")
        events_rejected_total.labels(reason="payload_too_large").inc()
        return JSONResponse(status_code=413, content={"detail": "Payload too large"})

    try:
        decoded = json.loads(body)
    except json.JSONDecodeError:
        await _audit_rejection(request, correlation_id, "malformed_json")
        events_rejected_total.labels(reason="malformed_json").inc()
        return JSONResponse(status_code=400, content={"detail": "Malformed JSON payload"})

    try:
        payload = EventIngestRequest.model_validate(decoded)
    except ValidationError as exc:
        await _audit_rejection(request, correlation_id, "schema_validation_failed")
        events_rejected_total.labels(reason="schema_validation_failed").inc()
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(exc.errors())})

    service = EventIngestionService(
        repository=_get_event_repository(request),
        normalizer=EventNormalizer(),
        audit=AuditService(request.app.state.audit_repository),
    )
    response = await service.ingest(payload, correlation_id=correlation_id)
    events_ingested_total.labels(
        category=response.category.value,
        severity=response.severity.value,
    ).inc()
    return response


def _get_event_repository(request: Request) -> EventRepository:
    return cast(EventRepository, request.app.state.event_repository)


async def _audit_rejection(request: Request, correlation_id: str, reason: str) -> None:
    await AuditService(request.app.state.audit_repository).record(
        AuditAction.EVENT_VALIDATION_FAILED,
        "failure",
        correlation_id=correlation_id,
        metadata={"reason": reason},
    )
