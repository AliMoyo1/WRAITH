"""Authority service configuration."""

from __future__ import annotations

import os

DB_URL_ENV = "WRAITH_DB_URL"
_DEFAULT_DB_URL = "sqlite:///./authority.db"


def database_url() -> str:
    """Return the database URL from the environment, or a local SQLite default.

    Production sets WRAITH_DB_URL to a PostgreSQL URL. Tests inject their own
    engine and do not rely on this default.
    """
    raw = os.environ.get(DB_URL_ENV)
    return raw.strip() if raw and raw.strip() else _DEFAULT_DB_URL
