"""Authentication API routes."""

from fastapi import APIRouter, Request, Response, status

from app.auth.schemas import LoginRequest, RefreshRequest, TokenPair
from app.core.dependencies.security import (
    build_authentication_service_from_request,
    resolve_current_user_from_request,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenPair)
async def login(
    payload: LoginRequest,
    request: Request,
) -> TokenPair:
    """Authenticate credentials and return an access/refresh token pair."""
    auth = build_authentication_service_from_request(request)
    return await auth.login(
        email=str(payload.email),
        password=payload.password,
        correlation_id=getattr(request.state, "correlation_id", None),
    )


@router.post("/refresh", response_model=TokenPair)
async def refresh(
    payload: RefreshRequest,
    request: Request,
) -> TokenPair:
    """Exchange a valid refresh token for a new token pair."""
    auth = build_authentication_service_from_request(request)
    return await auth.refresh(
        refresh_token=payload.refresh_token,
        correlation_id=getattr(request.state, "correlation_id", None),
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response,
) -> Response:
    """Record logout intent for the current user."""
    principal = await resolve_current_user_from_request(request)
    auth = build_authentication_service_from_request(request)
    correlation_id = getattr(request.state, "correlation_id", None)
    await auth.logout(actor=principal, correlation_id=correlation_id)
    return response
