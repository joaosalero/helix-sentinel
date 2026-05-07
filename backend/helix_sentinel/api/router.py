"""API router composition for versioned HTTP endpoints."""

from fastapi import APIRouter

from helix_sentinel.api.v1.health import router as health_router

api_router = APIRouter()
api_router.include_router(health_router, tags=["health"])

