"""Health endpoint API tests."""

from types import TracebackType
from typing import Self

from httpx import ASGITransport, AsyncClient

from helix_sentinel.core.config import Settings
from helix_sentinel.main import create_app


async def test_health_endpoint_returns_operational_metadata(client: AsyncClient) -> None:
    response = await client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "Helix Sentinel",
        "environment": "test",
    }
    assert "x-correlation-id" in response.headers


async def test_documented_runtime_mounts_feature_apis(client: AsyncClient) -> None:
    response = await client.get("/api/v1/security/me")

    assert response.status_code == 401


async def test_ready_endpoint_returns_ok_when_dependencies_respond() -> None:
    app = create_app(_test_settings())
    app.state.db_session_factory = _ReadySessionFactory()
    app.state.redis_client = _ReadyRedis()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
        response = await test_client.get("/api/v1/ready")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["dependencies"] == {"postgres": "ok", "redis": "ok"}


async def test_ready_endpoint_returns_503_when_dependency_fails() -> None:
    app = create_app(_test_settings())
    app.state.db_session_factory = _FailingSessionFactory()
    app.state.redis_client = _ReadyRedis()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
        response = await test_client.get("/api/v1/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "error"
    assert response.json()["dependencies"]["postgres"] == "error"


def _test_settings() -> Settings:
    return Settings(
        environment="test",
        secret_key="test-secret-key-with-at-least-32-bytes",
        database_url="postgresql+asyncpg://helix:helix@localhost:5432/helix_sentinel_test",
    )


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


class _FailingSession(_ReadySession):
    async def execute(self, _statement: object) -> None:
        raise RuntimeError("database unavailable")


class _FailingSessionFactory:
    def __call__(self) -> _FailingSession:
        return _FailingSession()


class _ReadyRedis:
    async def ping(self) -> bool:
        return True
