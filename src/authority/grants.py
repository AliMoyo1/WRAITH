"""Grant issuance and bearer encoding for the authority service.

Reuses the phase 1 entitlement primitives: the authority computes a principal's
capability set with ``capabilities_for`` and signs a short-lived
``CapabilityGrant``. The grant is the bearer credential clients carry.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import timedelta

from entitlement import CapabilityGrant, capabilities_for, now_utc

DEFAULT_GRANT_TTL_MINUTES = 15
DEFAULT_REFRESH_TTL_HOURS = 8


def issue_grant(
    key: bytes,
    tenant_id: str,
    principal_id: str,
    roles: list[str],
    tier: str,
    ttl_minutes: int = DEFAULT_GRANT_TTL_MINUTES,
) -> CapabilityGrant:
    """Compute the capability set for (roles, tier) and sign a short-lived grant."""
    capabilities = capabilities_for(roles, tier)
    return CapabilityGrant(
        tenant_id=tenant_id,
        principal_id=principal_id,
        roles=list(roles),
        tier=tier,
        capabilities=capabilities,
        issued_at=now_utc().isoformat(),
        expires_at=(now_utc() + timedelta(minutes=ttl_minutes)).isoformat(),
    ).sign(key)


def encode_grant(grant: CapabilityGrant) -> str:
    """Encode a grant as a URL-safe base64 bearer string."""
    raw = json.dumps(grant.to_dict()).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_grant(token: str) -> CapabilityGrant:
    """Decode a bearer string produced by encode_grant (does not verify)."""
    raw = base64.urlsafe_b64decode(token.encode("ascii"))
    return CapabilityGrant.from_dict(json.loads(raw))


def hash_refresh(raw: str) -> str:
    """Hash a refresh token for storage and lookup (never store the raw value)."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def new_refresh_token() -> tuple[str, str]:
    """Return (raw_token, sha256_hex). Store only the hash; hand out the raw once."""
    raw = secrets.token_urlsafe(32)
    return raw, hash_refresh(raw)
