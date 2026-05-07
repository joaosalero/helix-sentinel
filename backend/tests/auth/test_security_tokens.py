"""JWT token lifecycle tests."""

from uuid import uuid4

import pytest

from app.core.config.settings import SecuritySettings
from app.core.exceptions.security import AuthenticationError
from app.core.security.tokens import TokenService, TokenType


def test_access_token_round_trip() -> None:
    settings = SecuritySettings(
        environment="test",
        auth_secret_key="test-access-secret-with-at-least-32-bytes",
        auth_refresh_secret_key="test-refresh-secret-with-at-least-32-bytes",
    )
    service = TokenService(settings)

    token = service.create_access_token(
        subject=str(uuid4()),
        roles={"analyst"},
        permissions={"analytics:read"},
        token_id="token-1",
    )

    claims = service.validate(token, TokenType.ACCESS)
    assert claims.roles == frozenset({"analyst"})
    assert claims.permissions == frozenset({"analytics:read"})
    assert claims.token_id == "token-1"


def test_refresh_token_is_not_accepted_as_access_token() -> None:
    settings = SecuritySettings(
        environment="test",
        auth_secret_key="test-access-secret-with-at-least-32-bytes",
        auth_refresh_secret_key="test-refresh-secret-with-at-least-32-bytes",
    )
    service = TokenService(settings)
    token = service.create_refresh_token(subject=str(uuid4()), token_id="refresh-1")

    with pytest.raises(AuthenticationError):
        service.validate(token, TokenType.ACCESS)

