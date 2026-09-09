"""Password hashing for the authority service (Argon2id)."""

from __future__ import annotations

from argon2 import PasswordHasher

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Return True only if the password matches. Any failure verifies as False."""
    try:
        return _hasher.verify(hashed, password)
    except Exception:
        return False
