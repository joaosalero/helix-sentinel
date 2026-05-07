"""Password hashing and verification primitives."""

from typing import cast

from passlib.context import CryptContext

password_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2.

    Passwords must be validated by request schemas before this function is
    called. The returned hash is safe to store but must never be logged.
    """
    return cast(str, password_context.hash(password))


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a stored Argon2 hash."""
    return cast(bool, password_context.verify(password, password_hash))

