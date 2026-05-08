"""Compatibility wrapper for the authoritative Helix Sentinel app factory."""

from fastapi import FastAPI

from helix_sentinel.main import create_app


def create_security_app() -> FastAPI:
    """Return the single runtime app used by legacy feature API tests."""
    return create_app()
