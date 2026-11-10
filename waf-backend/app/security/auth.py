"""Admin password hashing and login tokens."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from ..config import get_settings

ALGORITHM = "HS256"
ISSUER = "hybrid-waf"
AUDIENCE = "hybrid-waf-admin"
MIN_PASSWORD_LENGTH = 12

_hasher = PasswordHasher()
# Verified when the username is unknown, so response time doesn't reveal valid usernames.
_DUMMY_HASH = _hasher.hash("timing-equalizer-not-a-real-password")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def create_token(username: str, token_version: int) -> tuple[str, int]:
    settings = get_settings()
    lifetime = settings.jwt_lifetime_minutes * 60
    now = datetime.now(UTC)
    payload = {
        "sub": username,
        "ver": token_version,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + timedelta(seconds=lifetime),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM), lifetime


def decode_token(token: str) -> dict:
    """Raises jwt.PyJWTError on anything invalid, and only ever accepts HS256."""
    return jwt.decode(
        token,
        get_settings().jwt_secret,
        algorithms=[ALGORITHM],
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"require": ["exp", "iat", "sub", "ver"]},
    )
