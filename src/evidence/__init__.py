"""WRAITH signed evidence bundles.

A portable, Ed25519-signed record of a scan that a consumer (ThemisIQ, an auditor)
verifies with the public key alone, independently of WRAITH. See bundle.py.
"""

from __future__ import annotations

from .bundle import EvidenceBundle, build_bundle, verify_bundle
from .keys import public_key, signing_key, signing_key_optional

__all__ = [
    "EvidenceBundle",
    "build_bundle",
    "public_key",
    "signing_key",
    "signing_key_optional",
    "verify_bundle",
]
