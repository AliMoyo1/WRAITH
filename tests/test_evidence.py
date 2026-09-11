"""Tests for signed evidence bundles: build, sign, verify, tamper detection."""

from __future__ import annotations

import base64
import copy
import json

from entitlement import generate_keypair
from evidence import EvidenceBundle, build_bundle, verify_bundle

PRIV, PUB = generate_keypair()

_ENGAGEMENT = {
    "id": "eng-1", "authorized_by": "op", "approved_at": "2026-09-11T00:00:00+00:00",
    "expires_at": "2026-09-12T00:00:00+00:00", "scope_fingerprint": "abc",
}
_ENTITLEMENT = {
    "tenant_id": "t-a", "principal_id": "p1", "roles": ["operator"], "tier": "enterprise",
    "capabilities": ["control_plane_scan"],
}
_ENGINES = [{"name": "skillspector", "version": "v1", "status": "OK", "coverage": "INTEGRATED"}]
_FINDINGS = [{
    "finding_id": "f1", "fingerprint": "fp1", "rule_id": "R1", "layer": 6,
    "severity": "HIGH", "confidence": "HIGH", "evaluation_result": "FINDING",
}]


def _bundle():
    # Deep-copy so a test that tampers a built bundle's findings never mutates the
    # shared module-level fixtures and pollutes another test.
    return build_bundle(
        copy.deepcopy(_ENGAGEMENT), copy.deepcopy(_ENTITLEMENT),
        copy.deepcopy(_ENGINES), copy.deepcopy(_FINDINGS),
    )


def test_build_sign_verify_roundtrip():
    b = _bundle().sign(PRIV)
    assert b.verify(PUB) is True
    assert b.completeness["finding_count"] == 1 and b.completeness["engine_count"] == 1
    assert b.completeness["statuses"] == {"OK": 1}


def test_unsigned_does_not_verify():
    assert _bundle().verify(PUB) is False


def test_wrong_key_does_not_verify():
    _other_priv, other_pub = generate_keypair()
    assert _bundle().sign(PRIV).verify(other_pub) is False


def test_tampered_finding_detected():
    b = _bundle().sign(PRIV)
    b.findings[0]["severity"] = "LOW"  # tamper after signing
    assert b.verify(PUB) is False


def test_to_from_dict_roundtrip():
    b = _bundle().sign(PRIV)
    b2 = EvidenceBundle.from_dict(b.to_dict())
    assert b2.verify(PUB) is True
    assert b2.content_digest == b.content_digest


def test_verify_bundle_standalone():
    data = _bundle().sign(PRIV).to_dict()
    assert verify_bundle(data, PUB) == (True, "ok")
    bad = {**data, "content_digest": "deadbeef"}
    ok, reason = verify_bundle(bad, PUB)
    assert ok is False and "digest" in reason


def test_verify_bundle_malformed():
    ok, reason = verify_bundle({"not": "a bundle"}, PUB)
    assert ok is False and "malformed" in reason


def test_null_entitlement_local_scan():
    b = build_bundle(_ENGAGEMENT, None, _ENGINES, _FINDINGS).sign(PRIV)
    assert b.verify(PUB) is True and b.entitlement is None


def test_cli_evidence_verify(tmp_path, monkeypatch):
    from cli import wraith

    b = _bundle().sign(PRIV)
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(b.to_dict()), encoding="utf-8")
    monkeypatch.setenv("WRAITH_EVIDENCE_PUBLIC_KEY", base64.urlsafe_b64encode(PUB).decode())
    assert wraith.main(["evidence", "verify", str(path)]) == 0

    tampered = b.to_dict()
    tampered["findings"][0]["severity"] = "LOW"
    path.write_text(json.dumps(tampered), encoding="utf-8")
    assert wraith.main(["evidence", "verify", str(path)]) == 2


def test_cli_evidence_verify_missing_key(tmp_path, monkeypatch):
    from cli import wraith

    monkeypatch.delenv("WRAITH_EVIDENCE_PUBLIC_KEY", raising=False)
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(_bundle().sign(PRIV).to_dict()), encoding="utf-8")
    assert wraith.main(["evidence", "verify", str(path)]) == 2  # missing public key
