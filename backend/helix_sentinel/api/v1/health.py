"""Operational health endpoints used by load balancers and local checks."""

from fastapi import APIRouter, Request
from pydantic import BaseModel

router = APIRouter()


class HealthResponse(BaseModel):
    """Public health response with non-sensitive operational metadata."""

    status: str
    service: str
    environment: str


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    """Return process health without touching external dependencies."""
    settings = request.app.state.settings
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        environment=settings.environment,
    )

