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
SIGNING_KEY_ENV = "WRAITH_RUNNER_SIGNING_KEY"
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


def signing_key() -> bytes:
    """Return the HMAC key the Runner uses to sign engagements and verify approval
    tokens, or raise.

    Read from WRAITH_RUNNER_SIGNING_KEY (no default, fail closed). The Runner is the
    only holder; it is distinct from the entitlement public key (grant verification)
    and the result-store key.
    """
    raw = os.environ.get(SIGNING_KEY_ENV)
    if not raw or not raw.strip():
        raise RuntimeError(
            f"{SIGNING_KEY_ENV} is not set. The Runner requires an engagement "
            "signing key to sign engagements and verify approval tokens."
        )
    return raw.encode("utf-8")


RESULT_KEY_ENV = "WRAITH_RUNNER_RESULT_KEY"
RESULTS_DIR_ENV = "WRAITH_RUNNER_RESULTS_DIR"
ENGINES_DIR_ENV = "WRAITH_RUNNER_ENGINES_DIR"
_DEFAULT_RESULTS_DIR = "./runner-results"
_DEFAULT_ENGINES_DIR = "repos"


def result_key() -> bytes:
    """Return the result-store master key, or raise (no default, fail closed).

    Findings are encrypted per scan under a key derived from this master key; the
    Runner is the only holder, distinct from the entitlement and engagement keys.
    """
    raw = os.environ.get(RESULT_KEY_ENV)
    if not raw or not raw.strip():
        raise RuntimeError(
            f"{RESULT_KEY_ENV} is not set. The Runner requires a result-store master key."
        )
    return raw.encode("utf-8")


def results_root() -> str:
    """Directory the Runner writes per-scan encrypted results under (has a default)."""
    raw = os.environ.get(RESULTS_DIR_ENV)
    return raw.strip() if raw and raw.strip() else _DEFAULT_RESULTS_DIR


def engines_dir() -> str:
    """Directory the operator installs the cloned engines under, server-side."""
    raw = os.environ.get(ENGINES_DIR_ENV)
    return raw.strip() if raw and raw.strip() else _DEFAULT_ENGINES_DIR
