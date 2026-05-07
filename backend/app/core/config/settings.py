"""Security-focused configuration for authentication and authorization."""

from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["local", "test", "staging", "production"]


class SecuritySettings(BaseSettings):
    """Authentication settings loaded from environment variables.

    Defaults are suitable for local development only. Non-local environments
    must provide rotated secrets through environment management.
    """

    model_config = SettingsConfigDict(env_prefix="HELIX_", env_file=".env", extra="ignore")

    environment: Environment = "local"
    auth_secret_key: str = Field(
        default="local-auth-development-secret-change-me-32b",
        min_length=32,
    )
    auth_refresh_secret_key: str = Field(
        default="local-refresh-development-secret-change-me-32b",
        min_length=32,
    )
    access_token_expire_minutes: int = Field(default=15, ge=1, le=120)
    refresh_token_expire_days: int = Field(default=14, ge=1, le=90)
    jwt_issuer: str = "helix-sentinel"
    jwt_audience: str = "helix-sentinel-api"

    @model_validator(mode="after")
    def reject_local_secrets_outside_local(self) -> Self:
        """Prevent accidental deployment with local development token secrets."""
        if self.environment != "local":
            local_secret = self.auth_secret_key.startswith("local-auth-development")
            local_refresh_secret = self.auth_refresh_secret_key.startswith(
                "local-refresh-development"
            )
            if local_secret or local_refresh_secret:
                msg = "HELIX_AUTH_SECRET_KEY and HELIX_AUTH_REFRESH_SECRET_KEY must be rotated"
                raise ValueError(msg)
        return self


@lru_cache
def get_security_settings() -> SecuritySettings:
    """Return cached security settings for dependency wiring."""
    return SecuritySettings()
