"""Runner service configuration.

The Runner verifies grants with the entitlement PUBLIC key only; the signing
secret lives solely in the authority and never reaches this service (see
docs/server-side-execution-scope.md section 4). The Runner's database is separate
from the authority's.
"""

from __future__ import annotations

import base64
import os

DB_URL_ENV = "WRAITH_RUNNER_DB_URL"
PUBLIC_KEY_ENV = "WRAITH_ENTITLEMENT_PUBLIC_KEY"
_DEFAULT_DB_URL = "sqlite:///./runner.db"


def database_url() -> str:
    """Return the Runner database URL, or a local SQLite default.

    Production sets WRAITH_RUNNER_DB_URL; tests inject their own engine and do not
    rely on this default. Distinct from the authority's database.
    """
    raw = os.environ.get(DB_URL_ENV)
    return raw.strip() if raw and raw.strip() else _DEFAULT_DB_URL


def entitlement_public_key() -> bytes:
    """Return the raw Ed25519 public key used to verify grants, or raise.

    Read from WRAITH_ENTITLEMENT_PUBLIC_KEY as url-safe base64 (32 raw bytes), the
    same encoding the authority uses for its private key. No default (fail closed):
    the Runner must be told which authority key to trust. The private key lives
    only in the authority and is never present here.
    """
    raw = os.environ.get(PUBLIC_KEY_ENV)
    if not raw or not raw.strip():
        raise RuntimeError(
            f"{PUBLIC_KEY_ENV} is not set. The Runner requires the entitlement "
            "public key to verify grants."
        )
    return base64.urlsafe_b64decode(raw.strip())
