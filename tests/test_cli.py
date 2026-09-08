"""CLI behaviour tests: scan enforces scope, exit codes are correct."""

from __future__ import annotations

import json
from pathlib import Path

import config
from cli import wraith


def _write_scope(path: Path, enabled: bool, domains: list[str]) -> None:
    path.write_text(
        json.dumps({"scope": {"enabled": enabled, "allowlist": {"domains": domains}}}),
        encoding="utf-8",
    )


def test_scan_out_of_scope_returns_2(tmp_path, capsys):
    scope = tmp_path / "scope.json"
    _write_scope(scope, True, ["example.com"])
    rc = wraith.main(["scan", "https://evil.test/x", "--scope", str(scope)])
    assert rc == 2
    assert "refused" in capsys.readouterr().out


def test_scan_in_scope_returns_0(tmp_path):
    scope = tmp_path / "scope.json"
    _write_scope(scope, True, ["example.com"])
    rc = wraith.main(["scan", "https://example.com/x", "--scope", str(scope)])
    assert rc == 0


def test_scan_scope_disabled_returns_2(tmp_path):
    scope = tmp_path / "scope.json"
    _write_scope(scope, False, ["example.com"])
    rc = wraith.main(["scan", "https://example.com/x", "--scope", str(scope)])
    assert rc == 2


def test_scan_missing_scope_returns_2(tmp_path):
    rc = wraith.main(["scan", "https://example.com/x", "--scope", str(tmp_path / "none.json")])
    assert rc == 2


def test_scope_add_persists(tmp_path):
    scope = tmp_path / "scope.json"
    rc = wraith.main(["scope", "add", "example.com", "--scope", str(scope)])
    assert rc == 0
    loaded = config.load_scope(scope)
    assert "example.com" in loaded.allow.domains


def test_kill_blocks_scan(tmp_path, monkeypatch):
    scope = tmp_path / "scope.json"
    _write_scope(scope, True, ["example.com"])
    monkeypatch.setattr(wraith, "_KILL_FLAG", tmp_path / ".killed")
    (tmp_path / ".killed").write_text("x", encoding="utf-8")
    rc = wraith.main(["scan", "https://example.com/x", "--scope", str(scope)])
    assert rc == 3


def test_engage_start_writes_signed_engagement(tmp_path, monkeypatch):
    monkeypatch.setenv(config.SIGNING_KEY_ENV, "operator-secret")
    scope = tmp_path / "scope.json"
    _write_scope(scope, True, ["example.com"])
    engage = tmp_path / "engagement.json"
    rc = wraith.main(
        ["engage", "start", "--by", "operator", "--scope", str(scope), "--engagement-file", str(engage)]
    )
    assert rc == 0
    eng = config.load_engagement(engage)
    ok, reason = eng.is_valid(b"operator-secret")
    assert ok is True, reason


def test_engage_start_without_key_returns_2(tmp_path, monkeypatch):
    monkeypatch.delenv(config.SIGNING_KEY_ENV, raising=False)
    scope = tmp_path / "scope.json"
    _write_scope(scope, True, ["example.com"])
    rc = wraith.main(
        ["engage", "start", "--by", "op", "--scope", str(scope), "--engagement-file", str(tmp_path / "e.json")]
    )
    assert rc == 2
