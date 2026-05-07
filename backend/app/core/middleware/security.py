"""Security middleware for correlation IDs, request logging, and headers."""

import logging
from collections.abc import Awaitable, Callable
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI, Request, Response

logger = logging.getLogger(__name__)


def register_security_middleware(app: FastAPI) -> None:
    """Install security-aware request middleware.

    Logs intentionally avoid request bodies and authorization headers because
    security analytics payloads and credentials may contain sensitive data.
    """

    @app.middleware("http")
    async def security_request_context(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        started_at = perf_counter()
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid4()))
        request.state.correlation_id = correlation_id

        response = await call_next(request)
        elapsed_ms = round((perf_counter() - started_at) * 1000, 2)
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store"

        logger.info(
            "HTTP request completed",
            extra={
                "correlation_id": correlation_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "elapsed_ms": elapsed_ms,
            },
        )
        return response

