"""Evidence signing and verification key configuration.

The producer holds the Ed25519 private key (WRAITH_EVIDENCE_PRIVATE_KEY); a verifier
(ThemisIQ, an auditor) holds only the public key (WRAITH_EVIDENCE_PUBLIC_KEY). Both
are url-safe base64 of the raw 32-byte key, with no default (fail closed), and are
distinct from the entitlement, engagement, and result keys.
"""

from __future__ import annotations

import base64
import os

PRIVATE_KEY_ENV = "WRAITH_EVIDENCE_PRIVATE_KEY"
PUBLIC_KEY_ENV = "WRAITH_EVIDENCE_PUBLIC_KEY"


def signing_key() -> bytes:
    """Return the evidence signing private key, or raise (no default)."""
    raw = os.environ.get(PRIVATE_KEY_ENV)
    if not raw or not raw.strip():
        raise RuntimeError(
            f"{PRIVATE_KEY_ENV} is not set. Signing an evidence bundle requires a private key."
        )
    return base64.urlsafe_b64decode(raw.strip())


def signing_key_optional() -> bytes | None:
    """Return the evidence signing key if configured, else None (evidence disabled).

    A producer (the Runner, the CLI) uses this to make evidence production optional:
    bundles are emitted only when a signing key is set.
    """
    raw = os.environ.get(PRIVATE_KEY_ENV)
    if not raw or not raw.strip():
        return None
    return base64.urlsafe_b64decode(raw.strip())


def public_key() -> bytes:
    """Return the evidence verification public key, or raise (no default)."""
    raw = os.environ.get(PUBLIC_KEY_ENV)
    if not raw or not raw.strip():
        raise RuntimeError(
            f"{PUBLIC_KEY_ENV} is not set. Verifying an evidence bundle requires the public key."
        )
    return base64.urlsafe_b64decode(raw.strip())
