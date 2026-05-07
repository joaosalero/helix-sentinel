"""FastAPI application factory for the Helix Sentinel modular monolith."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from helix_sentinel.api.router import api_router
from helix_sentinel.core.config import Settings, get_settings
from helix_sentinel.core.exceptions import register_exception_handlers
from helix_sentinel.core.logging import configure_logging
from helix_sentinel.core.middleware import register_middleware
from helix_sentinel.observability.metrics import metrics_router
from helix_sentinel.observability.telemetry import configure_tracing


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage process-level startup and shutdown hooks."""
    settings = get_settings()
    app.state.settings = settings
    yield


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create a configured FastAPI application instance.

    The factory keeps runtime wiring explicit and testable while preserving a
    modular monolith deployment model.
    """
    active_settings = settings or get_settings()
    configure_logging(active_settings)

    app = FastAPI(
        title=active_settings.app_name,
        version="0.1.0",
        docs_url="/docs" if active_settings.is_local else None,
        redoc_url="/redoc" if active_settings.is_local else None,
        openapi_url="/openapi.json" if active_settings.is_local else None,
        lifespan=lifespan,
    )
    app.state.settings = active_settings

    register_middleware(app, active_settings)
    register_exception_handlers(app)
    configure_tracing(app, active_settings)

    app.include_router(api_router, prefix=active_settings.api_prefix)
    app.include_router(metrics_router)
    return app


app = create_app()

