"""Tests for wraith doctor (readiness) and wraith scan --preview (outbound preview)."""

from __future__ import annotations

import json

import config
from cli import wraith


def _write_scope(path, enabled=True, domains=("example.com",)):
    path.write_text(
        json.dumps({"scope": {"enabled": enabled, "allowlist": {"domains": list(domains)}}}),
        encoding="utf-8",
    )


def test_doctor_clean_env_no_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv(config.SIGNING_KEY_ENV, raising=False)
    monkeypatch.delenv(config.RESULT_KEY_ENV, raising=False)
    monkeypatch.setattr(wraith, "_KILL_FLAG", tmp_path / ".killed")
    monkeypatch.setattr(wraith, "_SESSION_PATH", tmp_path / "session.json")
    rc = wraith.main([
        "doctor",
        "--scope", str(tmp_path / "none.json"),
        "--engagement-file", str(tmp_path / "none-eng.json"),
    ])
    out = capsys.readouterr().out
    assert rc == 0  # warnings only, no errors
    assert "summary:" in out and "kill-switch" in out


def test_doctor_reports_kill_and_scope(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(wraith, "_KILL_FLAG", tmp_path / ".killed")
    (tmp_path / ".killed").write_text("x", encoding="utf-8")
    monkeypatch.setattr(wraith, "_SESSION_PATH", tmp_path / "session.json")
    scope = tmp_path / "scope.json"
    _write_scope(scope, domains=("example.com", "test.example"))
    rc = wraith.main(["doctor", "--scope", str(scope), "--engagement-file", str(tmp_path / "none.json")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ENGAGED" in out and "2 allowlist entries" in out


def test_doctor_corrupt_scope_is_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(wraith, "_KILL_FLAG", tmp_path / ".killed")
    monkeypatch.setattr(wraith, "_SESSION_PATH", tmp_path / "session.json")
    scope = tmp_path / "scope.json"
    scope.write_text("[1, 2, 3]", encoding="utf-8")  # a list, not a scope mapping
    rc = wraith.main(["doctor", "--scope", str(scope), "--engagement-file", str(tmp_path / "none.json")])
    out = capsys.readouterr().out
    assert rc == 1 and "ERR" in out  # a parse error is an error-level check


def test_preview_in_scope(tmp_path, capsys):
    scope = tmp_path / "scope.json"
    _write_scope(scope, domains=("example.com",))
    rc = wraith.main(
        ["scan", "https://example.com/x", "--track", "all", "--preview", "--scope", str(scope)]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "IN SCOPE" in out and "outbound:" in out and "third parties" in out


def test_preview_out_of_scope(tmp_path, capsys):
    scope = tmp_path / "scope.json"
    _write_scope(scope, domains=("example.com",))
    rc = wraith.main(["scan", "https://evil.test/x", "--preview", "--scope", str(scope)])
    out = capsys.readouterr().out
    assert rc == 0  # preview reports; it does not fail on out-of-scope
    assert "OUT OF SCOPE" in out


def test_preview_repo_path_shows_engine_network(tmp_path, capsys):
    scope = tmp_path / "scope.json"
    _write_scope(scope, domains=("example.com",))
    rc = wraith.main(
        ["scan", "./somerepo", "--track", "sast", "--preview", "--scope", str(scope)]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "its contents are not uploaded" in out
    # The preview is egress-accurate: semgrep and trivy fetch rules and databases from
    # their vendors even for a local path scan.
    assert "network: semgrep" in out and "network: trivy" in out
    assert "third-party network calls" in out
