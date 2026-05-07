"""Centralized application configuration with explicit environment parsing."""

from functools import lru_cache
from typing import Literal, Self

from pydantic import AnyUrl, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["local", "test", "staging", "production"]


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables.

    Security-sensitive values must never be logged directly. Defaults are local
    development only and should be replaced through environment management in
    deployed environments.
    """

    model_config = SettingsConfigDict(env_prefix="HELIX_", env_file=".env", extra="ignore")

    app_name: str = "Helix Sentinel"
    environment: Environment = "local"
    api_prefix: str = "/api/v1"
    log_level: str = "INFO"
    secret_key: str = Field(default="local-development-secret-change-me-32b", min_length=32)
    access_token_expire_minutes: int = 30
    database_url: str = "postgresql+asyncpg://helix:helix@localhost:5432/helix_sentinel"
    redis_url: str = "redis://localhost:6379/0"
    allowed_origins: list[AnyUrl | str] = ["http://localhost:3000"]
    otel_enabled: bool = False
    prometheus_enabled: bool = True

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_allowed_origins(cls, value: str | list[str]) -> list[str] | list[AnyUrl | str]:
        """Support comma-separated origins in environment files."""
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @model_validator(mode="after")
    def reject_default_secret_outside_local(self) -> Self:
        """Prevent accidental promotion of the local development secret."""
        if self.environment != "local" and self.secret_key.startswith("local-development-secret"):
            msg = "HELIX_SECRET_KEY must be rotated outside local development"
            raise ValueError(msg)
        return self

    @property
    def is_local(self) -> bool:
        """Return whether developer-facing API metadata may be exposed."""
        return self.environment in {"local", "test"}


@lru_cache
def get_settings() -> Settings:
    """Return cached settings for application wiring."""
    return Settings()
