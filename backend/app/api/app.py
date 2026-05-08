"""Compatibility wrapper for the authoritative Helix Sentinel app factory."""

from fastapi import FastAPI

from app.audit.repositories import InMemoryAuditRepository
from helix_sentinel.main import create_app


def create_security_app() -> FastAPI:
    """Return the single runtime app used by legacy feature API tests."""
    app = create_app()
    app.state.audit_repository = InMemoryAuditRepository()
    return app
