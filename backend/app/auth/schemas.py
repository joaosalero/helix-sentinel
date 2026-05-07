"""Request and response schemas for authentication endpoints."""

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """Credential login request with strict password length boundaries."""

    email: str = Field(min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=8, max_length=256)


class RefreshRequest(BaseModel):
    """Refresh token exchange request."""

    refresh_token: str = Field(min_length=32)


class TokenPair(BaseModel):
    """Access and refresh tokens returned after authentication."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105
    expires_in: int
