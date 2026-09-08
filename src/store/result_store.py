"""Encrypted, per-engagement result store with a tamper-evident audit log.

WRAITH findings contain sensitive material (secrets, exploit paths, session
data), so the results store is as sensitive as the target. This module keeps
each engagement's findings encrypted at rest under a key derived per engagement,
restricts file permissions where the OS allows, records every read/write/export
in an append-only hash-chained audit log, and can purge an engagement on close.

WRAITH.md Section 11.5. This is target-read-only: all writes land under the
configured results root, never the scanned target.

Design:
  * Per-engagement key = HKDF(master_key, salt=engagement_id). Compromising one
    engagement's derived key does not reveal the master key or other engagements.
  * Findings are encrypted with Fernet (AES-128-CBC + HMAC-SHA256, authenticated).
  * The audit log is a chain: each entry carries the previous entry's MAC and its
    own HMAC over the body, so tampering and reordering are detectable. Tail
    truncation (dropping the most recent entries) needs an external tip anchor;
    record the latest MAC in a separate protected location to detect that.

The master key must come from an operator secret (WRAITH_RESULT_KEY); there is no
default.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_AUDIT_GENESIS = "genesis"


class ResultStoreError(Exception):
    """Raised for missing findings, decryption failure, or bad configuration."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _derive_key(master_key: bytes, engagement_id: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=engagement_id.encode("utf-8"),
        info=b"wraith-result-store-v1",
    )
    return base64.urlsafe_b64encode(hkdf.derive(master_key))


class ResultStore:
    """Encrypted per-engagement result store."""

    def __init__(self, root: str | Path, engagement_id: str, master_key: bytes, actor: str = "unknown"):
        if not master_key:
            raise ResultStoreError("master_key is required; do not run with a default key")
        if not engagement_id or not engagement_id.strip():
            raise ResultStoreError("engagement_id is required")
        self.engagement_id = engagement_id
        self.actor = actor or "unknown"
        self.key = _derive_key(master_key, engagement_id)
        self._fernet = Fernet(self.key)
        # A distinct key for the audit MAC so audit integrity is independent of content encryption.
        self._audit_key = hashlib.sha256(b"wraith-audit-v1:" + self.key).digest()
        self.dir = Path(root) / engagement_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self._restrict(self.dir, is_dir=True)
        self.audit_path = self.dir / "audit.log"

    # ---- permissions -----------------------------------------------------
    @staticmethod
    def _restrict(path: Path, is_dir: bool = False) -> None:
        # Best effort. POSIX honors this; on Windows chmod only toggles the
        # read-only bit, so the results root should also be ACL-protected.
        try:
            os.chmod(path, 0o700 if is_dir else 0o600)
        except OSError:
            pass

    def _finding_path(self, finding_id: str) -> Path:
        # Keep the id filesystem-safe.
        safe = "".join(c for c in finding_id if c.isalnum() or c in "-_.")
        if not safe:
            raise ResultStoreError("invalid finding id")
        return self.dir / f"{safe}.enc"

    # ---- findings --------------------------------------------------------
    def put_finding(self, finding: dict) -> str:
        finding_id = str(finding.get("finding_id") or uuid.uuid4())
        finding = {**finding, "finding_id": finding_id}
        token = self._fernet.encrypt(_canonical(finding))
        path = self._finding_path(finding_id)
        path.write_bytes(token)
        self._restrict(path)
        self._append_audit("put", finding_id=finding_id)
        return finding_id

    def get_finding(self, finding_id: str) -> dict:
        path = self._finding_path(finding_id)
        if not path.exists():
            raise ResultStoreError(f"no such finding: {finding_id}")
        try:
            plaintext = self._fernet.decrypt(path.read_bytes())
        except InvalidToken as exc:
            self._append_audit("get_failed", finding_id=finding_id)
            raise ResultStoreError("decryption failed (wrong key or tampered ciphertext)") from exc
        self._append_audit("get", finding_id=finding_id)
        return json.loads(plaintext)

    def list_findings(self) -> list[str]:
        return sorted(p.stem for p in self.dir.glob("*.enc"))

    def export(self, out_path: str | Path) -> Path:
        findings = []
        for finding_id in self.list_findings():
            token = self._finding_path(finding_id).read_bytes()
            try:
                findings.append(json.loads(self._fernet.decrypt(token)))
            except InvalidToken as exc:
                raise ResultStoreError(f"decryption failed for {finding_id}") from exc
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = {"engagement_id": self.engagement_id, "findings": findings}
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self._restrict(out)
        self._append_audit("export", count=len(findings), destination=str(out))
        return out

    def purge(self) -> None:
        """Remove all stored results for this engagement (call on engagement close)."""
        self._append_audit("purge")
        shutil.rmtree(self.dir, ignore_errors=True)

    # ---- audit log (append-only hash chain) ------------------------------
    def read_audit(self) -> list[dict]:
        if not self.audit_path.exists():
            return []
        entries = []
        for line in self.audit_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                entries.append(json.loads(line))
        return entries

    def _append_audit(self, event: str, **fields: object) -> None:
        entries = self.read_audit()
        prev = entries[-1]["mac"] if entries else _AUDIT_GENESIS
        body = {"seq": len(entries), "ts": _now(), "actor": self.actor, "event": event, "prev": prev, **fields}
        mac = hmac.new(self._audit_key, _canonical(body), hashlib.sha256).hexdigest()
        entry = {**body, "mac": mac}
        with open(self.audit_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        self._restrict(self.audit_path)

    def verify_audit(self) -> bool:
        """Return True if the audit chain is intact.

        Detects modification and reordering of entries. Tail truncation is not
        detectable from the log alone (see the module note on tip anchoring).
        """
        prev = _AUDIT_GENESIS
        for entry in self.read_audit():
            mac = entry.get("mac")
            body = {k: v for k, v in entry.items() if k != "mac"}
            if body.get("prev") != prev:
                return False
            expected = hmac.new(self._audit_key, _canonical(body), hashlib.sha256).hexdigest()
            if not isinstance(mac, str) or not hmac.compare_digest(expected, mac):
                return False
            prev = mac
        return True
