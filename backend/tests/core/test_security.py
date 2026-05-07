"""Security primitive tests."""

import jwt

from helix_sentinel.core.config import Settings
from helix_sentinel.security.passwords import hash_password, verify_password
from helix_sentinel.security.tokens import create_access_token


def test_password_hashing_round_trip() -> None:
    password_hash = hash_password("correct horse battery staple")

    assert password_hash != "correct horse battery staple"
    assert verify_password("correct horse battery staple", password_hash)
    assert not verify_password("wrong password", password_hash)


def test_access_token_contains_subject(test_settings: Settings) -> None:
    token = create_access_token("user-123", test_settings, {"scope": "detections:read"})

    decoded = jwt.decode(token, test_settings.secret_key, algorithms=["HS256"])
    assert decoded["sub"] == "user-123"
    assert decoded["scope"] == "detections:read"

