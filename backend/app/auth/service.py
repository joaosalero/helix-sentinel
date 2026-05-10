"""Authentication service for credential and refresh-token flows."""

from dataclasses import dataclass
from secrets import token_urlsafe
from uuid import UUID, uuid4

from app.audit.events import AuditAction
from app.audit.service import AuditService
from app.auth.schemas import TokenPair
from app.core.config.settings import SecuritySettings
from app.core.exceptions.security import AuthenticationError
from app.core.security.passwords import hash_password, verify_password
from app.core.security.tokens import TokenService, TokenType
from app.users.models import UserStatus
from app.users.repositories import UserRepository
from app.users.schemas import Principal

DUMMY_PASSWORD_HASH = hash_password(token_urlsafe(32))


@dataclass(frozen=True)
class RefreshTokenRecord:
    """Refresh-token state used to prepare rotation and revocation."""

    token_id: str
    user_id: str
    revoked: bool = False


class AuthenticationService:
    """Authenticate users and issue JWT token pairs.

    The service avoids account enumeration by returning the same public failure
    for missing users, invalid passwords, and inactive accounts.
    """

    def __init__(
        self,
        users: UserRepository,
        tokens: TokenService,
        audit: AuditService,
        settings: SecuritySettings,
    ) -> None:
        self.users = users
        self.tokens = tokens
        self.audit = audit
        self.settings = settings

    async def login(
        self,
        email: str,
        password: str,
        *,
        correlation_id: str | None,
    ) -> TokenPair:
        """Validate credentials and issue a short-lived access/refresh pair."""
        user = await self.users.get_by_email(email)
        password_hash = user.password_hash if user is not None else DUMMY_PASSWORD_HASH
        valid_password = verify_password(password, password_hash)
        active_user = user is not None and user.status == UserStatus.ACTIVE

        if not valid_password or not active_user or user is None:
            await self.audit.record(
                AuditAction.LOGIN_FAILED,
                "failure",
                actor_email=email,
                correlation_id=correlation_id,
                metadata={"reason": "invalid_credentials_or_state"},
            )
            raise AuthenticationError

        token_pair = self._issue_token_pair(user.to_principal())
        await self.audit.record(
            AuditAction.LOGIN_SUCCEEDED,
            "success",
            actor_id=user.id,
            actor_email=user.email,
            correlation_id=correlation_id,
            metadata={"tenant_id": user.tenant_id},
        )
        return token_pair

    async def refresh(self, refresh_token: str, *, correlation_id: str | None) -> TokenPair:
        """Validate a refresh token and issue a rotated token pair.

        Persistent refresh-token storage can later mark the old `jti` as used.
        The token claim is already present so rotation can be introduced without
        changing API contracts.
        """
        claims = self.tokens.validate(refresh_token, TokenType.REFRESH)
        user = await self.users.get_by_id(claims_subject_as_uuid(claims.subject))
        if user is None or user.status != UserStatus.ACTIVE:
            await self.audit.record(
                AuditAction.USER_STATE_REJECTED,
                "failure",
                actor_email=None,
                correlation_id=correlation_id,
            )
            raise AuthenticationError

        token_pair = self._issue_token_pair(user.to_principal())
        await self.audit.record(
            AuditAction.TOKEN_REFRESHED,
            "success",
            actor_id=user.id,
            actor_email=user.email,
            correlation_id=correlation_id,
            metadata={"previous_token_id": claims.token_id, "tenant_id": user.tenant_id},
        )
        return token_pair

    async def logout(self, *, actor: Principal, correlation_id: str | None) -> None:
        """Record logout intent.

        Stateless access tokens remain valid until expiry; refresh-token
        revocation storage should be added before enabling long-lived sessions.
        """
        await self.audit.record(
            AuditAction.LOGOUT_REQUESTED,
            "success",
            actor_id=actor.id,
            actor_email=actor.email,
            correlation_id=correlation_id,
            metadata={"tenant_id": actor.tenant_id},
        )

    def _issue_token_pair(self, principal: Principal) -> TokenPair:
        token_id = str(uuid4())
        access_token = self.tokens.create_access_token(
            subject=str(principal.id),
            roles=set(principal.roles),
            permissions=set(principal.permissions),
            token_id=token_id,
        )
        refresh_token = self.tokens.create_refresh_token(
            subject=str(principal.id),
            token_id=token_id,
        )
        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self.settings.access_token_expire_minutes * 60,
        )


def claims_subject_as_uuid(subject: str) -> UUID:
    """Convert token subject to UUID while normalizing validation failures."""
    try:
        return UUID(subject)
    except ValueError as exc:
        raise AuthenticationError from exc
