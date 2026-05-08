"""Health endpoint API tests."""

from httpx import AsyncClient


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
