"""Grant issuance and bearer encoding for the authority service.

Reuses the phase 1 entitlement primitives: the authority computes a principal's
capability set with ``capabilities_for`` and signs a short-lived
``CapabilityGrant``. The grant is the bearer credential clients carry.
"""

from __future__ import annotations

import hashlib
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
    exclude: frozenset[str] = frozenset(),
    extra: frozenset[str] = frozenset(),
) -> CapabilityGrant:
    """Compute the capability set for (roles, tier) and sign a short-lived grant.

    ``exclude`` drops capability classes from the computed set, used to cap the
    classes an API-key grant may carry. ``extra`` adds issuance-context capability
    classes that do not come from the role-by-tier matrix, used to mark an
    interactive login so that API-key-derived grants cannot manage API keys.
    """
    capabilities = sorted((set(capabilities_for(roles, tier)) - exclude) | extra)
    return CapabilityGrant(
        tenant_id=tenant_id,
        principal_id=principal_id,
        roles=list(roles),
        tier=tier,
        capabilities=capabilities,
        issued_at=now_utc().isoformat(),
        expires_at=(now_utc() + timedelta(minutes=ttl_minutes)).isoformat(),
    ).sign(key)


def hash_refresh(raw: str) -> str:
    """Hash a refresh token for storage and lookup (never store the raw value)."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def new_refresh_token() -> tuple[str, str]:
    """Return (raw_token, sha256_hex). Store only the hash; hand out the raw once."""
    raw = secrets.token_urlsafe(32)
    return raw, hash_refresh(raw)


_API_KEY_PREFIX = "wak_"


def hash_api_key(raw: str) -> str:
    """Hash an API key for storage and lookup (never store the raw value)."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def new_api_key() -> tuple[str, str]:
    """Return (raw_key, sha256_hex). The raw key carries a 'wak_' prefix."""
    raw = _API_KEY_PREFIX + secrets.token_urlsafe(32)
    return raw, hash_api_key(raw)
