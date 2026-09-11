"""Tests for the Runner client, driven against an in-process Runner app."""

from __future__ import annotations

from datetime import timedelta

import pytest

from adapters import AdapterResult, EngineAdapter, SubprocessResult
from entitlement import CapabilityGrant, encode_grant, generate_keypair, now_utc

PRIV, PUB = generate_keypair()
SIGN_KEY = b"rc-sign-key"
RESULT_KEY = b"rc-result-key"
PLATFORM_KEY = b"rc-platform-key"


class _FakeAdapter(EngineAdapter):
    name = "skillspector"

    def is_available(self):
        return True, "ok"

    def _default_runner(self, request):
        return SubprocessResult(0, "", "")

    def _normalize(self, raw):
        return []

    def run(self, request, runner=None):
        return AdapterResult(
            engine=self.name,
            status="OK",
            findings=[
                {
                    "finding_id": "f1", "fingerprint": "fp1", "rule_id": "R1", "layer": 6,
                    "severity": "HIGH", "confidence": "HIGH", "evaluation_result": "FINDING",
                }
            ],
        )


@pytest.fixture
def client(tmp_path):
    from fastapi.testclient import TestClient

    from client import RunnerClient
    from runner import create_app
    from runner.db import create_all, make_engine, make_session_factory
    from runner.worker import InlineExecutor

    engine = make_engine(f"sqlite:///{tmp_path / 'runner.db'}")
    create_all(engine)
    factory = make_session_factory(engine)
    app = create_app(
        session_factory=factory,
        entitlement_public_key=PUB,
        signing_key=SIGN_KEY,
        result_key=RESULT_KEY,
        result_root=tmp_path / "results",
        executor=InlineExecutor(),
        adapters_for=lambda track: [_FakeAdapter()],
        platform_key=PLATFORM_KEY,
    )
    return RunnerClient("http://runner", http_client=TestClient(app))


def _grant(tenant="t-a", caps=("control_plane_scan", "control_plane_read")):
    grant = CapabilityGrant(
        tenant_id=tenant,
        principal_id="p1",
        roles=["operator"],
        tier="enterprise",
        capabilities=list(caps),
        issued_at=now_utc().isoformat(),
        expires_at=(now_utc() + timedelta(hours=1)).isoformat(),
    ).sign(PRIV)
    return encode_grant(grant)


def test_engagement_and_scan_roundtrip(client):
    grant = _grant()
    eng = client.create_engagement(grant, "op", {"allowlist": {"domains": ["example.com"]}})
    assert eng["open"] is True
    assert client.get_engagement(grant, eng["id"])["valid"] is True

    scan = client.create_scan(grant, eng["id"], "https://example.com/x", "sast")
    result = client.wait_for_scan(grant, scan["id"])
    assert result["status"] == "completed"
    assert {f["finding_id"] for f in result["findings"]} == {"f1"}

    assert any(s["id"] == scan["id"] for s in client.list_scans(grant)["scans"])


def test_close_engagement(client):
    grant = _grant()
    eng = client.create_engagement(grant, "op", {"allowlist": {"domains": ["example.com"]}})
    assert client.close_engagement(grant, eng["id"])["open"] is False


def test_error_surfaces(client):
    from client import RunnerError

    with pytest.raises(RunnerError):
        client.get_scan(_grant(), "nonexistent")


def test_cli_runner_requires_login(tmp_path, monkeypatch):
    from cli import wraith

    monkeypatch.setattr(wraith, "_SESSION_PATH", tmp_path / "nope.json")
    assert wraith.main(["runner", "scans"]) == 2  # not logged in
