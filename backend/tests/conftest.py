"""Shared pytest fixtures for Helix Sentinel backend tests."""

from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient

from helix_sentinel.core.config import Settings
from helix_sentinel.main import create_app


@pytest.fixture
def test_settings() -> Settings:
    """Return isolated test settings without requiring a local `.env` file."""
    return Settings(
        environment="test",
        secret_key="test-secret-key-with-at-least-32-bytes",
        database_url="postgresql+asyncpg://helix:helix@localhost:5432/helix_sentinel_test",
    )


@pytest.fixture
async def client(test_settings: Settings) -> AsyncIterator[AsyncClient]:
    """Create an async client for API contract tests."""
    transport = ASGITransport(app=create_app(test_settings))
    async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
        yield test_client
