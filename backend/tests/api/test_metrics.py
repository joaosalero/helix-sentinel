"""Metrics endpoint API tests."""

from httpx import AsyncClient


async def test_metrics_endpoint_is_prometheus_compatible(client: AsyncClient) -> None:
    response = await client.get("/metrics")

    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
