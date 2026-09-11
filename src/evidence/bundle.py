"""Signed, portable evidence bundles.

An evidence bundle is a self-contained, signed record of a scan: the engagement that
authorized it, the entitlement grant (if any), the engines that ran and their pinned
versions, the findings, and a completeness summary. It is signed with Ed25519 so a
consumer (ThemisIQ, an auditor) verifies it with the public key alone, without any
shared secret and independently of WRAITH. See docs/server-side-execution-scope.md
section 11.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime

from entitlement import sign_bytes, verify_bytes

_VERSION = 1


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _content_digest(findings: list[dict], engines: list[dict]) -> str:
    """A stable digest over the evidence content (engines + findings)."""
    return hashlib.sha256(_canonical({"engines": engines, "findings": findings})).hexdigest()


@dataclass
class EvidenceBundle:
    """A scan's signed evidence. The signature covers the whole payload, and the
    content_digest pins the engines and findings, so any tampering is detectable."""

    engagement: dict
    entitlement: dict | None
    engines: list[dict]
    findings: list[dict]
    completeness: dict
    content_digest: str
    created_at: str
    version: int = _VERSION
    signature: str | None = None

    def _payload(self) -> dict:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "engagement": self.engagement,
            "entitlement": self.entitlement,
            "engines": self.engines,
            "findings": self.findings,
            "completeness": self.completeness,
            "content_digest": self.content_digest,
        }

    def sign(self, private_key: bytes) -> EvidenceBundle:
        self.signature = sign_bytes(private_key, _canonical(self._payload()))
        return self

    def verify(self, public_key: bytes) -> bool:
        if not self.signature:
            return False
        if _content_digest(self.findings, self.engines) != self.content_digest:
            return False
        return verify_bytes(public_key, self.signature, _canonical(self._payload()))

    def to_dict(self) -> dict:
        return {**self._payload(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: dict) -> EvidenceBundle:
        return cls(
            engagement=data["engagement"],
            entitlement=data.get("entitlement"),
            engines=list(data.get("engines", [])),
            findings=list(data.get("findings", [])),
            completeness=data.get("completeness", {}),
            content_digest=data["content_digest"],
            created_at=data.get("created_at", ""),
            version=int(data.get("version", _VERSION)),
            signature=data.get("signature"),
        )


def build_bundle(
    engagement: dict,
    entitlement: dict | None,
    engine_results: list[dict],
    findings: list[dict],
) -> EvidenceBundle:
    """Assemble an unsigned evidence bundle from a scan's parts.

    ``engine_results`` are per-engine summaries, for example
    {"name": ..., "version": ..., "status": ..., "coverage": ...}.
    """
    statuses: dict[str, int] = {}
    for result in engine_results:
        status = str(result.get("status", "UNKNOWN"))
        statuses[status] = statuses.get(status, 0) + 1
    completeness = {
        "finding_count": len(findings),
        "engine_count": len(engine_results),
        "statuses": statuses,
    }
    return EvidenceBundle(
        engagement=engagement,
        entitlement=entitlement,
        engines=engine_results,
        findings=findings,
        completeness=completeness,
        content_digest=_content_digest(findings, engine_results),
        created_at=datetime.now(UTC).isoformat(),
    )


def verify_bundle(data: dict, public_key: bytes) -> tuple[bool, str]:
    """Standalone verifier: check a serialized bundle's digest and signature.

    Returns (ok, reason). Fail closed: a malformed, unsigned, tampered, or
    wrong-key bundle is a deny with a reason.
    """
    try:
        bundle = EvidenceBundle.from_dict(data)
    except (KeyError, TypeError, ValueError) as exc:
        return False, f"malformed bundle: {exc}"
    if not bundle.signature:
        return False, "bundle is not signed"
    if _content_digest(bundle.findings, bundle.engines) != bundle.content_digest:
        return False, "content digest does not match engines and findings"
    if not verify_bytes(public_key, bundle.signature, _canonical(bundle._payload())):
        return False, "signature invalid"
    return True, "ok"
