"""Configuration validation tests."""

import pytest
from pydantic import ValidationError

from helix_sentinel.core.config import Settings


def test_settings_parse_comma_separated_origins() -> None:
    settings = Settings(
        environment="test",
        secret_key="test-secret-key-with-at-least-32-bytes",
        allowed_origins="http://localhost:3000,https://sentinel.example.com",
    )

    assert [str(origin) for origin in settings.allowed_origins] == [
        "http://localhost:3000",
        "https://sentinel.example.com",
    ]


def test_default_secret_is_rejected_outside_local() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="production")
