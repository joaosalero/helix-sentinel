"""Redis client factory for cache, rate-limit, and worker integration."""

from redis.asyncio import Redis

from helix_sentinel.core.config import Settings


def create_redis_client(settings: Settings) -> Redis:
    """Create a Redis client without connecting during import time."""
    return Redis.from_url(str(settings.redis_url), encoding="utf-8", decode_responses=True)

