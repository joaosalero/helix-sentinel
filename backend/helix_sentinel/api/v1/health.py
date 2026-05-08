"""Operational health endpoints used by load balancers and local checks."""

import logging
from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text

logger = logging.getLogger(__name__)

router = APIRouter()


class HealthResponse(BaseModel):
    """Public health response with non-sensitive operational metadata."""

    status: str
    service: str
    environment: str


DependencyState = Literal["ok", "error"]


class ReadinessResponse(BaseModel):
    """Dependency readiness response without sensitive connection metadata."""

    status: DependencyState
    service: str
    environment: str
    dependencies: dict[str, DependencyState]


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    """Return process health without touching external dependencies."""
    settings = request.app.state.settings
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        environment=settings.environment,
    )


@router.get("/ready", response_model=ReadinessResponse)
async def ready(request: Request) -> ReadinessResponse | JSONResponse:
    """Return dependency readiness for local orchestration and operators."""
    settings = request.app.state.settings
    dependencies = {
        "postgres": await _check_postgres(request),
        "redis": await _check_redis(request),
    }
    status: DependencyState = (
        "ok" if all(value == "ok" for value in dependencies.values()) else "error"
    )
    response = ReadinessResponse(
        status=status,
        service=settings.app_name,
        environment=settings.environment,
        dependencies=dependencies,
    )
    if status == "error":
        return JSONResponse(status_code=503, content=response.model_dump())
    return response


async def _check_postgres(request: Request) -> DependencyState:
    session_factory = getattr(request.app.state, "db_session_factory", None)
    if session_factory is None:
        return "error"
    try:
        async with session_factory() as session:
            await session.execute(text("SELECT 1"))
    except Exception:
        logger.warning(
            "PostgreSQL readiness check failed",
            extra={"correlation_id": getattr(request.state, "correlation_id", None)},
        )
        return "error"
    return "ok"


async def _check_redis(request: Request) -> DependencyState:
    redis_client = getattr(request.app.state, "redis_client", None)
    if redis_client is None:
        return "error"
    try:
        pong = await redis_client.ping()
    except Exception:
        logger.warning(
            "Redis readiness check failed",
            extra={"correlation_id": getattr(request.state, "correlation_id", None)},
        )
        return "error"
    return "ok" if pong else "error"
