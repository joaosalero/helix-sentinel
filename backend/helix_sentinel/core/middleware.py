"""HTTP middleware for security headers, CORS, and request correlation."""

from collections.abc import Awaitable, Callable
from uuid import uuid4

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from helix_sentinel.core.config import Settings


def register_middleware(app: FastAPI, settings: Settings) -> None:
    """Register cross-cutting HTTP middleware.

    Security headers are intentionally conservative and can be tightened per
    deployment once frontend origins and asset policies are finalized.
    """
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.allowed_origins],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Correlation-ID"],
    )

    @app.middleware("http")
    async def correlation_and_security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid4()))
        request.state.correlation_id = correlation_id
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

