"""Authority service configuration."""

from __future__ import annotations

import base64
import os

DB_URL_ENV = "WRAITH_DB_URL"
ENTITLEMENT_PRIVATE_KEY_ENV = "WRAITH_ENTITLEMENT_PRIVATE_KEY"
MFA_KEY_ENV = "WRAITH_MFA_KEY"
_DEFAULT_DB_URL = "sqlite:///./authority.db"


def database_url() -> str:
    """Return the database URL from the environment, or a local SQLite default.

    Production sets WRAITH_DB_URL to a PostgreSQL URL. Tests inject their own
    engine and do not rely on this default.
    """
    raw = os.environ.get(DB_URL_ENV)
    return raw.strip() if raw and raw.strip() else _DEFAULT_DB_URL


def entitlement_private_key() -> bytes:
    """Return the Ed25519 grant-signing private key from the environment, or raise.

    The authority is the only holder of the private key: it signs grants with it
    and derives the public key to verify its own bearer grants. Stored base64-url
    encoded (32 raw bytes). No default (fail closed).
    """
    raw = os.environ.get(ENTITLEMENT_PRIVATE_KEY_ENV)
    if not raw or not raw.strip():
        raise RuntimeError(
            f"{ENTITLEMENT_PRIVATE_KEY_ENV} is not set. The authority requires an "
            "Ed25519 private key to sign grants."
        )
    return base64.urlsafe_b64decode(raw.strip())


def mfa_key() -> bytes:
    """Return the Fernet key used to encrypt MFA secrets and sign challenges.

    Must be a valid Fernet key (32 url-safe base64 bytes). No default (fail
    closed); distinct from the entitlement, signing, and result keys.
    """
    raw = os.environ.get(MFA_KEY_ENV)
    if not raw or not raw.strip():
        raise RuntimeError(
            f"{MFA_KEY_ENV} is not set. The authority requires a Fernet key to "
            "protect MFA secrets."
        )
    return raw.strip().encode("utf-8")
