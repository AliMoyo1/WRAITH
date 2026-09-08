"""Result-store tests: encryption at rest, key isolation, tamper-evident audit."""

from __future__ import annotations

import json

import pytest

from store import ResultStore, ResultStoreError

MASTER = b"operator-result-master-key"
EID = "eng-123"


def _store(tmp_path, master=MASTER, eid=EID, actor="tester") -> ResultStore:
    return ResultStore(tmp_path / "results", eid, master, actor=actor)


def test_put_get_roundtrip(tmp_path):
    s = _store(tmp_path)
    fid = s.put_finding({"finding_id": "f1", "title": "SQLi", "severity": "HIGH"})
    assert fid == "f1"
    got = s.get_finding("f1")
    assert got["title"] == "SQLi" and got["severity"] == "HIGH"


def test_missing_master_key_refused(tmp_path):
    with pytest.raises(ResultStoreError):
        ResultStore(tmp_path / "results", EID, b"", actor="x")


def test_ciphertext_is_not_plaintext(tmp_path):
    s = _store(tmp_path)
    s.put_finding({"finding_id": "f1", "secret": "SUPERSECRETVALUE"})
    raw = (s.dir / "f1.enc").read_bytes()
    assert b"SUPERSECRETVALUE" not in raw
    assert b"secret" not in raw


def test_wrong_key_cannot_decrypt(tmp_path):
    _store(tmp_path, master=MASTER).put_finding({"finding_id": "f1", "x": 1})
    other = _store(tmp_path, master=b"a-different-master-key")
    with pytest.raises(ResultStoreError):
        other.get_finding("f1")


def test_per_engagement_key_isolation(tmp_path):
    a = _store(tmp_path, eid="engA")
    b = _store(tmp_path, eid="engB")
    assert a.key != b.key


def test_list_findings(tmp_path):
    s = _store(tmp_path)
    s.put_finding({"finding_id": "f1"})
    s.put_finding({"finding_id": "f2"})
    assert s.list_findings() == ["f1", "f2"]


def test_export_decrypts_all(tmp_path):
    s = _store(tmp_path)
    s.put_finding({"finding_id": "f1", "severity": "HIGH"})
    s.put_finding({"finding_id": "f2", "severity": "LOW"})
    out = s.export(tmp_path / "out.json")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["engagement_id"] == EID
    assert {f["finding_id"] for f in data["findings"]} == {"f1", "f2"}


def test_audit_records_and_verifies(tmp_path):
    s = _store(tmp_path)
    s.put_finding({"finding_id": "f1"})
    s.get_finding("f1")
    s.export(tmp_path / "out.json")
    events = [e["event"] for e in s.read_audit()]
    assert events == ["put", "get", "export"]
    assert s.verify_audit() is True


def test_audit_tamper_detected(tmp_path):
    s = _store(tmp_path)
    s.put_finding({"finding_id": "f1"})
    s.get_finding("f1")
    lines = s.audit_path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["actor"] = "attacker"  # change a signed field, leave the mac
    lines[0] = json.dumps(first, sort_keys=True)
    s.audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert s.verify_audit() is False


def test_tail_truncation_detected(tmp_path):
    s = _store(tmp_path)
    s.put_finding({"finding_id": "f1"})
    s.put_finding({"finding_id": "f2"})
    s.put_finding({"finding_id": "f3"})
    assert s.verify_audit() is True
    # Drop the most recent audit entry; the (unforgeable) tip still points past it.
    lines = s.audit_path.read_text(encoding="utf-8").splitlines()
    s.audit_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    assert s.verify_audit() is False


def test_missing_tip_detected(tmp_path):
    s = _store(tmp_path)
    s.put_finding({"finding_id": "f1"})
    s.tip_path.unlink()
    assert s.verify_audit() is False


def test_forged_tip_rejected(tmp_path):
    s = _store(tmp_path)
    s.put_finding({"finding_id": "f1"})
    s.put_finding({"finding_id": "f2"})
    lines = s.audit_path.read_text(encoding="utf-8").splitlines()
    s.audit_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    # An attacker without the audit key cannot recompute a matching tip_mac.
    s.tip_path.write_text(json.dumps({"seq": 0, "mac": "x", "tip_mac": "forged"}), encoding="utf-8")
    assert s.verify_audit() is False


def test_external_tip_anchor(tmp_path):
    external = tmp_path / "anchors" / "eng.tip"
    s = ResultStore(tmp_path / "results", EID, MASTER, actor="t", tip_anchor_path=external)
    s.put_finding({"finding_id": "f1"})
    assert external.exists()
    assert s.verify_audit() is True


def test_empty_audit_is_valid(tmp_path):
    s = _store(tmp_path)
    assert s.verify_audit() is True  # no log and no tip


def test_failed_get_is_audited(tmp_path):
    _store(tmp_path, master=MASTER).put_finding({"finding_id": "f1", "x": 1})
    other = _store(tmp_path, master=b"wrong-key")
    with pytest.raises(ResultStoreError):
        other.get_finding("f1")
    assert any(e["event"] == "get_failed" for e in other.read_audit())


def test_purge_removes_results(tmp_path):
    s = _store(tmp_path)
    s.put_finding({"finding_id": "f1"})
    assert s.dir.exists()
    s.purge()
    assert not s.dir.exists()


def test_cli_report_without_key_returns_2(monkeypatch):
    from cli import wraith
    monkeypatch.delenv("WRAITH_RESULT_KEY", raising=False)
    assert wraith.main(["report", "eng-x"]) == 2


def test_cli_report_summarizes_and_exports(tmp_path, monkeypatch):
    from cli import wraith
    monkeypatch.setenv("WRAITH_RESULT_KEY", "cli-master-key")
    monkeypatch.setattr(wraith, "_RESULTS_ROOT", tmp_path / "results")
    seed = ResultStore(tmp_path / "results", "eng-x", b"cli-master-key", actor="seed")
    seed.put_finding({"finding_id": "f1", "severity": "HIGH"})
    out = tmp_path / "report.json"
    rc = wraith.main(["report", "eng-x", "--export", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["findings"][0]["finding_id"] == "f1"
