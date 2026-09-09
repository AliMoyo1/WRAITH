"""Engagement records and action approval tokens.

An Engagement is a signed, expiring authorization manifest for one assessment.
It is required before any Layer 8-9 (exploitation / post-exploitation) work.
The earlier skeleton accepted a blank approver and blank timestamps and had no
signature or expiry, so a retained closed engagement could still be routed.

Everything here is deterministic standard-library code (hmac / hashlib). The
signing key is provided by the caller; it must come from an operator secret
(environment variable or keyring), never a hard-coded default.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .scope import Scope


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
class Engagement:
    """Per-assessment authorization record. Sign it before use; verify on load."""

    id: str
    authorized_by: str
    approved_at: str  # ISO 8601
    expires_at: str  # ISO 8601
    scope: Scope
    open: bool = True
    signature: str | None = None

    def _payload(self) -> dict:
        return {
            "id": self.id,
            "authorized_by": self.authorized_by.strip(),
            "approved_at": self.approved_at,
            "expires_at": self.expires_at,
            "scope_fingerprint": self.scope.fingerprint(),
        }

    def sign(self, key: bytes) -> Engagement:
        self.signature = _sign(key, self._payload())
        return self

    def verify(self, key: bytes) -> bool:
        if not self.signature:
            return False
        expected = _sign(key, self._payload())
        return hmac.compare_digest(expected, self.signature)

    def is_valid(self, key: bytes, at: datetime | None = None) -> tuple[bool, str]:
        """Return (ok, reason). A false ok always carries a reason string."""
        at = at or now_utc()
        if not self.id or not self.id.strip():
            return False, "engagement id is blank"
        if not self.authorized_by or not self.authorized_by.strip():
            return False, "authorized_by is blank"
        approved = _parse_iso(self.approved_at)
        if approved is None:
            return False, "approved_at is missing or unparseable"
        if approved > at:
            return False, "approved_at is in the future"
        expires = _parse_iso(self.expires_at)
        if expires is None:
            return False, "expires_at is missing or unparseable"
        if expires <= at:
            return False, "engagement has expired"
        if not self.open:
            return False, "engagement is closed"
        if not self.scope.enabled:
            return False, "scope is not enabled"
        if not self.verify(key):
            return False, "engagement signature is invalid"
        return True, "ok"


@dataclass
class ApprovalToken:
    """Single-use, action-and-target-specific approval for a consequential action.

    Bound to one engagement, one action (for example "exploit"), and one target.
    Consumed exactly once by the orchestrator to prevent replay.
    """

    engagement_id: str
    action: str
    target: str
    expires_at: str
    nonce: str = field(default_factory=lambda: secrets.token_hex(16))
    signature: str | None = None

    def _payload(self) -> dict:
        return {
            "engagement_id": self.engagement_id,
            "action": self.action,
            "target": self.target,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
        }

    def sign(self, key: bytes) -> ApprovalToken:
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

    def to_dict(self) -> dict:
        """Serialize to a plain dict, including the nonce and signature.

        A token must be transported whole: verification recomputes the MAC over
        every signed field (the nonce and expiry included), so a bare signature
        cannot be reconstructed or checked on its own.
        """
        return {**self._payload(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: dict) -> ApprovalToken:
        """Rebuild a token from ``to_dict`` output, preserving the signed nonce."""
        return cls(
            engagement_id=data["engagement_id"],
            action=data["action"],
            target=data["target"],
            expires_at=data["expires_at"],
            nonce=data.get("nonce", ""),
            signature=data.get("signature"),
        )
