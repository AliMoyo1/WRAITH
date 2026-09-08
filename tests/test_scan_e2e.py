"""End-to-end `wraith scan` orchestration: engagement -> supervisor -> store -> report."""

from __future__ import annotations

import json

from adapters.base import AdapterResult, EngineAdapter, SubprocessResult


class FakeAdapter(EngineAdapter):
    name = "skillspector"

    def is_available(self):
        return True, "ok"

    def _default_runner(self, request):
        return SubprocessResult(0, "[]", "")

    def _normalize(self, raw):
        return []

    def run(self, request, runner=None):
        return AdapterResult(
            engine=self.name,
            status="OK",
            findings=[
                {"finding_id": "f1", "fingerprint": "fp1", "rule_id": "PE3", "engine": "skillspector",
                 "layer": 6, "severity": "HIGH", "confidence": "HIGH", "evaluation_result": "FINDING"},
                {"finding_id": "f2", "fingerprint": "fp2", "rule_id": "P1", "engine": "skillspector",
                 "layer": 7, "severity": "LOW", "confidence": "LOW", "evaluation_result": "FINDING"},
            ],
        )


def _write_scope(path, repo):
    path.write_text(
        json.dumps({"scope": {"enabled": True, "allowlist": {"repo_paths": [str(repo)]}}}),
        encoding="utf-8",
    )


def test_scan_stores_findings_under_engagement(tmp_path, monkeypatch):
    from cli import wraith
    monkeypatch.setenv("WRAITH_SIGNING_KEY", "sign-key")
    monkeypatch.setenv("WRAITH_RESULT_KEY", "result-key")
    repo = tmp_path / "repo"
    repo.mkdir()
    scope = tmp_path / "scope.json"
    _write_scope(scope, repo)
    engf = tmp_path / "engagement.json"
    start = ["engage", "start", "--by", "tester", "--scope", str(scope), "--engagement-file", str(engf)]
    assert wraith.main(start) == 0

    monkeypatch.setattr(wraith, "_RESULTS_ROOT", tmp_path / "results")
    monkeypatch.setattr(wraith, "_KILL_FLAG", tmp_path / ".killed")
    monkeypatch.setattr(wraith, "_build_adapter", lambda name: (FakeAdapter(), None))
    out = tmp_path / "report.json"
    rc = wraith.main(["scan", str(repo), "--engagement-file", str(engf), "--report", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert {f["finding_id"] for f in data["findings"]} == {"f1", "f2"}
    assert data["engagement_id"]  # persisted under the engagement


def test_scan_without_engagement_is_ephemeral(tmp_path, monkeypatch):
    from cli import wraith
    repo = tmp_path / "repo"
    repo.mkdir()
    scope = tmp_path / "scope.json"
    _write_scope(scope, repo)
    monkeypatch.setattr(wraith, "_KILL_FLAG", tmp_path / ".killed")
    monkeypatch.setattr(wraith, "_build_adapter", lambda name: (FakeAdapter(), None))
    out = tmp_path / "eph.json"
    rc = wraith.main([
        "scan", str(repo), "--scope", str(scope),
        "--engagement-file", str(tmp_path / "none.json"), "--report", str(out),
    ])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["engagement_id"] is None and len(data["findings"]) == 2


def test_scan_out_of_scope_under_engagement_refused(tmp_path, monkeypatch):
    from cli import wraith
    monkeypatch.setenv("WRAITH_SIGNING_KEY", "sign-key")
    repo = tmp_path / "repo"
    repo.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    scope = tmp_path / "scope.json"
    _write_scope(scope, repo)
    engf = tmp_path / "engagement.json"
    assert wraith.main(["engage", "start", "--by", "t", "--scope", str(scope), "--engagement-file", str(engf)]) == 0
    monkeypatch.setattr(wraith, "_KILL_FLAG", tmp_path / ".killed")
    rc = wraith.main(["scan", str(other), "--engagement-file", str(engf)])
    assert rc == 2


def test_scan_kill_switch_blocks(tmp_path, monkeypatch):
    from cli import wraith
    kill = tmp_path / ".killed"
    kill.write_text("x", encoding="utf-8")
    monkeypatch.setattr(wraith, "_KILL_FLAG", kill)
    assert wraith.main(["scan", str(tmp_path / "repo")]) == 3


def test_adapters_for_selection():
    from cli import wraith
    assert wraith._adapters_for("all", "https://example.com/x") == ["strix"]
    assert wraith._adapters_for("all", "/home/user/repo") == ["skillspector"]
    assert wraith._adapters_for("sast", "anything") == ["skillspector"]
    assert wraith._adapters_for("web", "anything") == ["strix"]
