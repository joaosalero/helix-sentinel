"""FastAPI application factory for the auth/RBAC security foundation."""

from fastapi import FastAPI

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
from app.core.middleware.security import register_security_middleware
from app.detections.repositories import InMemoryDetectionRuleRepository
from app.enrichment.repositories import InMemoryIOCRepository
from app.events.repositories import InMemoryEventRepository
from app.users.repositories import InMemoryUserRepository


def create_security_app() -> FastAPI:
    """Create an isolated app used by authentication and RBAC tests."""
    app = FastAPI(title="Helix Sentinel Security")
    app.state.user_repository = InMemoryUserRepository()
    app.state.audit_repository = InMemoryAuditRepository()
    app.state.event_repository = InMemoryEventRepository()
    app.state.detection_rule_repository = InMemoryDetectionRuleRepository()
    app.state.ioc_repository = InMemoryIOCRepository()
    app.state.security_settings = get_security_settings()
    register_security_middleware(app)
    register_security_exception_handlers(app)
    app.include_router(ai_router, prefix="/api/v1")
    app.include_router(analytics_router, prefix="/api/v1")
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(detections_router, prefix="/api/v1")
    app.include_router(enrichment_router, prefix="/api/v1")
    app.include_router(events_router, prefix="/api/v1")
    app.include_router(security_probe_router, prefix="/api/v1")
    app.include_router(threats_router, prefix="/api/v1")
    return app
