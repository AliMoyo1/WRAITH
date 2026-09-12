"""Tests for the Agent BOM: inventory, risk summary, sign/verify, and the CLI."""

from __future__ import annotations

import base64
import json

from agentbom import AgentBOM, build_bom, verify_bom
from entitlement import generate_keypair

PRIV, PUB = generate_keypair()

_DESC = {
    "name": "recon-agent",
    "model": "claude-opus-4-8",
    "tools": [
        {"name": "web_fetch", "effects": "read"},
        {"name": "shell", "effects": "execute"},
        {"name": "write_file", "effects": "write"},
    ],
    "data_sources": [
        {"name": "internal-kb", "external": False},
        {"name": "public-web", "external": True},
    ],
    "mcp_servers": [{"name": "filesystem", "url": "stdio://fs"}],
    "permissions": ["read:repo", "net:outbound"],
}


def test_build_inventory_and_summary():
    bom = build_bom(_DESC)
    assert bom.agent == "recon-agent" and bom.model == "claude-opus-4-8"
    assert bom.summary["counts"] == {"tool": 3, "data_source": 2, "mcp_server": 1, "permission": 2}
    flags = bom.summary["risk_flags"]
    assert flags["state_changing_tools"] == ["shell", "write_file"]
    assert flags["external_data_sources"] == ["public-web"]
    assert flags["mcp_servers"] == ["filesystem"]
    assert flags["outbound_network"] is True


def test_sign_verify_roundtrip():
    assert build_bom(_DESC).sign(PRIV).verify(PUB) is True


def test_tamper_detected():
    bom = build_bom(_DESC).sign(PRIV)
    bom.components.append({"type": "tool", "name": "evil", "effects": "execute"})
    assert bom.verify(PUB) is False


def test_wrong_key_does_not_verify():
    _other_priv, other_pub = generate_keypair()
    assert build_bom(_DESC).sign(PRIV).verify(other_pub) is False


def test_to_from_dict_roundtrip():
    bom = build_bom(_DESC).sign(PRIV)
    assert AgentBOM.from_dict(bom.to_dict()).verify(PUB) is True


def test_verify_bom_standalone_and_malformed():
    data = build_bom(_DESC).sign(PRIV).to_dict()
    assert verify_bom(data, PUB) == (True, "ok")
    assert verify_bom({"nope": 1}, PUB)[0] is False


def test_no_outbound_when_absent():
    bom = build_bom({"name": "a", "permissions": ["read:repo"]})
    assert bom.summary["risk_flags"]["outbound_network"] is False


def test_cli_build_summary(tmp_path, capsys):
    from cli import wraith

    desc = tmp_path / "desc.json"
    desc.write_text(json.dumps(_DESC), encoding="utf-8")
    assert wraith.main(["agentbom", "build", str(desc)]) == 0
    out = capsys.readouterr().out
    assert "recon-agent" in out and "state_changing_tools" in out and "shell" in out


def test_cli_build_signed_and_verify(tmp_path, monkeypatch):
    from cli import wraith

    desc = tmp_path / "desc.json"
    desc.write_text(json.dumps(_DESC), encoding="utf-8")
    bom_path = tmp_path / "bom.json"
    monkeypatch.setenv("WRAITH_EVIDENCE_PRIVATE_KEY", base64.urlsafe_b64encode(PRIV).decode())
    monkeypatch.setenv("WRAITH_EVIDENCE_PUBLIC_KEY", base64.urlsafe_b64encode(PUB).decode())
    assert wraith.main(["agentbom", "build", str(desc), "--out", str(bom_path)]) == 0
    assert wraith.main(["agentbom", "verify", str(bom_path)]) == 0

    data = json.loads(bom_path.read_text(encoding="utf-8"))
    data["components"].append({"type": "tool", "name": "x", "effects": "execute"})
    bom_path.write_text(json.dumps(data), encoding="utf-8")
    assert wraith.main(["agentbom", "verify", str(bom_path)]) == 2
