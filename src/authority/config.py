"""Authority service configuration."""

from __future__ import annotations

import os

DB_URL_ENV = "WRAITH_DB_URL"
ENTITLEMENT_KEY_ENV = "WRAITH_ENTITLEMENT_KEY"
_DEFAULT_DB_URL = "sqlite:///./authority.db"


def database_url() -> str:
    """Return the database URL from the environment, or a local SQLite default.

    Production sets WRAITH_DB_URL to a PostgreSQL URL. Tests inject their own
    engine and do not rely on this default.
    """
    raw = os.environ.get(DB_URL_ENV)
    return raw.strip() if raw and raw.strip() else _DEFAULT_DB_URL


def entitlement_key() -> bytes:
    """Return the entitlement signing key from the environment, or raise.

    The authority is the only holder of this key: it signs grants with it and
    verifies incoming grants against it. Distinct from the CLI signing and result
    keys, and there is no default (fail closed).
    """
    raw = os.environ.get(ENTITLEMENT_KEY_ENV)
    if not raw or not raw.strip():
        raise RuntimeError(
            f"{ENTITLEMENT_KEY_ENV} is not set. The authority requires an "
            "entitlement signing key to issue and verify grants."
        )
    return raw.encode("utf-8")
