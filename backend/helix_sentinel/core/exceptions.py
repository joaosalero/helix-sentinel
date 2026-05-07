"""Centralized exception handling for predictable API failures."""

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class DomainError(Exception):
    """Base exception for expected domain failures."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        self.message = message
        self.status_code = status_code
        super().__init__(message)


def register_exception_handlers(app: FastAPI) -> None:
    """Register sanitized error responses.

    Internal exception details are logged server-side and are never returned to
    clients because platform data may contain sensitive security telemetry.
    """

    @app.exception_handler(DomainError)
    async def domain_error_handler(_request: Request, exc: DomainError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception(
            "Unhandled application error",
            extra={"correlation_id": getattr(request.state, "correlation_id", None)},
        )
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

