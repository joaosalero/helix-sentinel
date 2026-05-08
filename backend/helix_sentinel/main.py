"""FastAPI application factory for the Helix Sentinel modular monolith."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.ai.repositories import InMemoryAIEventRepository
from app.api.routes.ai import router as ai_router
from app.api.routes.analytics import router as analytics_router
from app.api.routes.auth import router as auth_router
from app.api.routes.detections import router as detections_router
from app.api.routes.enrichment import router as enrichment_router
from app.api.routes.events import router as events_router
from app.api.routes.security_probe import router as security_probe_router
from app.api.routes.threats import router as threats_router
from app.audit.repositories import InMemoryAuditRepository
from app.core.config.settings import get_security_settings
from app.core.exceptions.security import register_security_exception_handlers
from app.detections.repositories import InMemoryDetectionRuleRepository
from app.enrichment.repositories import InMemoryIOCRepository
from app.events.repositories import InMemoryEventRepository
from app.users.repositories import PostgresUserRepository
from helix_sentinel.api.router import api_router
from helix_sentinel.core.config import Settings, get_settings
from helix_sentinel.core.exceptions import register_exception_handlers
from helix_sentinel.core.logging import configure_logging
from helix_sentinel.core.middleware import register_middleware
from helix_sentinel.db.session import create_session_factory
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
    configure_feature_state(app, active_settings)

    register_middleware(app, active_settings)
    register_security_exception_handlers(app)
    register_exception_handlers(app)
    configure_tracing(app, active_settings)

    app.include_router(api_router, prefix=active_settings.api_prefix)
    include_feature_routers(app, active_settings.api_prefix)
    app.include_router(metrics_router)
    return app


def configure_feature_state(app: FastAPI, settings: Settings) -> None:
    """Install local adapters required by the implemented feature modules."""
    event_repository = InMemoryEventRepository()
    app.state.db_session_factory = create_session_factory(str(settings.database_url))
    app.state.user_repository = PostgresUserRepository(app.state.db_session_factory)
    app.state.audit_repository = InMemoryAuditRepository()
    app.state.event_repository = event_repository
    app.state.detection_rule_repository = InMemoryDetectionRuleRepository()
    app.state.ioc_repository = InMemoryIOCRepository()
    app.state.ai_event_repository = InMemoryAIEventRepository(event_repository.normalized_events)
    app.state.security_settings = get_security_settings()


def include_feature_routers(app: FastAPI, api_prefix: str) -> None:
    """Mount implemented product APIs on the authoritative application factory."""
    app.include_router(ai_router, prefix=api_prefix)
    app.include_router(analytics_router, prefix=api_prefix)
    app.include_router(auth_router, prefix=api_prefix)
    app.include_router(detections_router, prefix=api_prefix)
    app.include_router(enrichment_router, prefix=api_prefix)
    app.include_router(events_router, prefix=api_prefix)
    app.include_router(security_probe_router, prefix=api_prefix)
    app.include_router(threats_router, prefix=api_prefix)


app = create_app()
