"""Capability grants: signed, expiring RBAC and subscription entitlement.

A CapabilityGrant states which capability classes a principal (within a tenant)
may use. The authority computes that set from the principal's roles and the
tenant tier (see ``policy.capabilities_for``), then signs the grant.

Grants are signed with Ed25519: the authority holds the private key and signs;
every verifier (the authority itself, and the Runner) holds only the public key.
The signing secret therefore lives in exactly one place. See
docs/server-side-execution-scope.md section 4.

This is orthogonal to the engagement gate: a grant NEVER authorizes a target,
only a capability class. See docs/entitlement-rbac-subscription.md.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


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


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private_key, public_key) as raw 32-byte Ed25519 keys."""
    sk = Ed25519PrivateKey.generate()
    return sk.private_bytes_raw(), sk.public_key().public_bytes_raw()


def public_from_private(private_key: bytes) -> bytes:
    """Derive the raw public key from a raw Ed25519 private key."""
    return Ed25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()


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

    def sign(self, private_key: bytes) -> CapabilityGrant:
        signer = Ed25519PrivateKey.from_private_bytes(private_key)
        raw = signer.sign(_canonical(self._payload()))
        self.signature = base64.urlsafe_b64encode(raw).decode("ascii")
        return self

    def verify(self, public_key: bytes) -> bool:
        if not self.signature:
            return False
        try:
            verifier = Ed25519PublicKey.from_public_bytes(public_key)
            verifier.verify(base64.urlsafe_b64decode(self.signature), _canonical(self._payload()))
            return True
        except (InvalidSignature, ValueError):
            return False

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
