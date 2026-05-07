"""JWT token helpers prepared for authentication flows."""

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from helix_sentinel.core.config import Settings


def create_access_token(
    subject: str,
    settings: Settings,
    claims: dict[str, Any] | None = None,
) -> str:
    """Create a signed access token with minimal trusted claims."""
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.access_token_expire_minutes)).timestamp()),
    }
    if claims:
        payload.update(claims)
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")
