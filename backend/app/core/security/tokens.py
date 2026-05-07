"""JWT access and refresh token lifecycle helpers."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

import jwt

from app.core.config.settings import SecuritySettings
from app.core.exceptions.security import AuthenticationError


class TokenType(StrEnum):
    """Supported token classes with separate signing keys."""

    ACCESS = "access"
    REFRESH = "refresh"


@dataclass(frozen=True)
class TokenClaims:
    """Trusted claims extracted from a validated token."""

    subject: str
    token_type: TokenType
    roles: frozenset[str]
    permissions: frozenset[str]
    token_id: str | None


class TokenService:
    """Create and validate JWTs for Helix Sentinel authentication flows."""

    def __init__(self, settings: SecuritySettings) -> None:
        self.settings = settings

    def create_access_token(
        self,
        subject: str,
        roles: set[str],
        permissions: set[str],
        token_id: str | None = None,
    ) -> str:
        """Create a short-lived access token for API authorization."""
        expires_at = datetime.now(UTC) + timedelta(
            minutes=self.settings.access_token_expire_minutes
        )
        return self._encode(
            subject=subject,
            token_type=TokenType.ACCESS,
            expires_at=expires_at,
            claims={
                "roles": sorted(roles),
                "permissions": sorted(permissions),
                "jti": token_id,
            },
        )

    def create_refresh_token(self, subject: str, token_id: str) -> str:
        """Create a refresh token prepared for rotation and revocation tracking."""
        expires_at = datetime.now(UTC) + timedelta(days=self.settings.refresh_token_expire_days)
        return self._encode(
            subject=subject,
            token_type=TokenType.REFRESH,
            expires_at=expires_at,
            claims={"jti": token_id},
        )

    def validate(self, token: str, expected_type: TokenType) -> TokenClaims:
        """Validate a JWT and return trusted authorization claims."""
        secret = self._secret_for(expected_type)
        try:
            payload = jwt.decode(
                token,
                secret,
                algorithms=["HS256"],
                audience=self.settings.jwt_audience,
                issuer=self.settings.jwt_issuer,
            )
        except jwt.PyJWTError as exc:
            raise AuthenticationError from exc

        token_type = payload.get("typ")
        subject = payload.get("sub")
        if token_type != expected_type.value or not isinstance(subject, str):
            raise AuthenticationError

        roles = payload.get("roles", [])
        permissions = payload.get("permissions", [])
        return TokenClaims(
            subject=subject,
            token_type=expected_type,
            roles=frozenset(str(role) for role in roles if isinstance(role, str)),
            permissions=frozenset(
                str(permission) for permission in permissions if isinstance(permission, str)
            ),
            token_id=payload.get("jti") if isinstance(payload.get("jti"), str) else None,
        )

    def _encode(
        self,
        subject: str,
        token_type: TokenType,
        expires_at: datetime,
        claims: dict[str, Any],
    ) -> str:
        now = datetime.now(UTC)
        payload = {
            "sub": subject,
            "typ": token_type.value,
            "iss": self.settings.jwt_issuer,
            "aud": self.settings.jwt_audience,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            **claims,
        }
        secret = self._secret_for(token_type)
        return jwt.encode(payload, secret, algorithm="HS256")

    def _secret_for(self, token_type: TokenType) -> str:
        if token_type is TokenType.ACCESS:
            return self.settings.auth_secret_key
        return self.settings.auth_refresh_secret_key
