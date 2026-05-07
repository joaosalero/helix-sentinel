"""Password hashing primitives for future identity flows."""

from typing import cast

from passlib.context import CryptContext

password_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a password using a memory-hard algorithm."""
    return cast(str, password_context.hash(password))


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password without exposing timing-sensitive comparison details."""
    return cast(bool, password_context.verify(password, password_hash))
