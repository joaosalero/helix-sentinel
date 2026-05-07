"""Security exception types and sanitized API error handlers."""

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Raised when credentials or tokens cannot authenticate a principal."""


class AuthorizationError(Exception):
    """Raised when an authenticated principal lacks required access."""


def register_security_exception_handlers(app: FastAPI) -> None:
    """Register safe security error responses without leaking sensitive details."""

    @app.exception_handler(AuthenticationError)
    async def authentication_error_handler(
        _request: Request,
        _exc: AuthenticationError,
    ) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})

    @app.exception_handler(AuthorizationError)
    async def authorization_error_handler(
        request: Request,
        _exc: AuthorizationError,
    ) -> JSONResponse:
        logger.info(
            "Permission denied",
            extra={"correlation_id": getattr(request.state, "correlation_id", None)},
        )
        return JSONResponse(status_code=403, content={"detail": "Permission denied"})
