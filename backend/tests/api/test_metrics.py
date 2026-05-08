"""Metrics endpoint API tests."""

from types import TracebackType
from typing import Self

from httpx import ASGITransport, AsyncClient

from helix_sentinel.core.config import Settings
from helix_sentinel.main import create_app


async def test_metrics_endpoint_is_prometheus_compatible(client: AsyncClient) -> None:
    response = await client.get("/metrics")

    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    assert "helix_http_requests_total" in response.text


async def test_readiness_dependency_metrics_are_exposed(client: AsyncClient) -> None:
    app = create_app(
        Settings(
            environment="test",
            secret_key="test-secret-key-with-at-least-32-bytes",
            database_url="postgresql+asyncpg://helix:helix@localhost:5432/helix_sentinel_test",
        )
    )
    app.state.db_session_factory = _ReadySessionFactory()
    app.state.redis_client = _ReadyRedis()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
        await test_client.get("/api/v1/ready")
        response = await test_client.get("/metrics")

    assert response.status_code == 200
    assert "helix_readiness_dependency_status" in response.text
    assert "helix_readiness_dependency_duration_seconds" in response.text


class _ReadySession:
    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None

    async def execute(self, _statement: object) -> None:
        return None


class _ReadySessionFactory:
    def __call__(self) -> _ReadySession:
        return _ReadySession()


class _ReadyRedis:
    async def ping(self) -> bool:
        return True
