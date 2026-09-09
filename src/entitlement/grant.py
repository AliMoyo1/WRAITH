"""Capability grants: signed, expiring RBAC and subscription entitlement.

A CapabilityGrant states which capability classes a principal (within a tenant)
may use. The authority computes that set from the principal's roles and the
tenant tier (see ``policy.capabilities_for``), then signs the grant. Verification
is deterministic standard-library HMAC, mirroring ``orchestrator.engagement``.

This is orthogonal to the engagement gate: a grant NEVER authorizes a target,
only a capability class. See docs/entitlement-rbac-subscription.md.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime


def now_utc() -> datetime:
    return datetime.now(UTC)


def _parse_iso(value: str) -> datetime | None:
    if not value or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _sign(key: bytes, payload: dict) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, raw, hashlib.sha256).hexdigest()


@dataclass
class CapabilityGrant:
    """A signed, expiring statement of the capability classes a principal holds.

    Bound to one tenant and one principal. Short-lived and renewable, not
    single-use. The ``capabilities`` list is authoritative: the authority
    computes and writes it, and verifiers only check membership.
    """

    tenant_id: str
    principal_id: str
    roles: list[str]
    tier: str
    capabilities: list[str]
    issued_at: str  # ISO 8601
    expires_at: str  # ISO 8601
    version: int = 1
    nonce: str = field(default_factory=lambda: secrets.token_hex(16))
    signature: str | None = None

    def _payload(self) -> dict:
        # Sort the list fields so the signature is independent of their order.
        return {
            "version": self.version,
            "tenant_id": self.tenant_id,
            "principal_id": self.principal_id,
            "roles": sorted(self.roles),
            "tier": self.tier,
            "capabilities": sorted(self.capabilities),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
        }

    def sign(self, key: bytes) -> CapabilityGrant:
        self.signature = _sign(key, self._payload())
        return self

    def verify(self, key: bytes) -> bool:
        if not self.signature:
            return False
        expected = _sign(key, self._payload())
        return hmac.compare_digest(expected, self.signature)

    def is_expired(self, at: datetime | None = None) -> bool:
        expires = _parse_iso(self.expires_at)
        if expires is None:
            return True
        return expires <= (at or now_utc())

    def allows(self, capability_class: str) -> bool:
        return capability_class in self.capabilities

    def to_dict(self) -> dict:
        return {**self._payload(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: dict) -> CapabilityGrant:
        return cls(
            tenant_id=data["tenant_id"],
            principal_id=data["principal_id"],
            roles=list(data.get("roles", [])),
            tier=data["tier"],
            capabilities=list(data.get("capabilities", [])),
            issued_at=data.get("issued_at", ""),
            expires_at=data.get("expires_at", ""),
            version=int(data.get("version", 1)),
            nonce=data.get("nonce", ""),
            signature=data.get("signature"),
        )
