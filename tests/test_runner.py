"""Tests for the Runner skeleton: health, public-key grant verification, the
capability-class check, and tenant isolation.

Grants are built and signed here with a test private key; the Runner is given only
the matching public key, mirroring production where the signing secret never
reaches the Runner.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from adapters import AdapterResult, EngineAdapter, SubprocessResult
from entitlement import CapabilityGrant, encode_grant, generate_keypair, now_utc

PRIV, PUB = generate_keypair()
SIGN_KEY = b"runner-engagement-signing-key"
RESULT_KEY = b"runner-result-master-key"
PLATFORM_KEY = b"platform-operator-key"
_SCAN_CAPS = ("control_plane_scan", "control_plane_read")


class _FakeScanAdapter(EngineAdapter):
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


def _fake_adapters(track):
    return [_FakeScanAdapter()]


@pytest.fixture
def runner(tmp_path):
    from fastapi.testclient import TestClient

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
        adapters_for=_fake_adapters,
        platform_key=PLATFORM_KEY,
    )
    return TestClient(app), factory


def _bearer(
    tenant: str = "t-a",
    caps: tuple[str, ...] = ("control_plane_read",),
    priv: bytes = PRIV,
    hours: float = 1.0,
) -> str:
    grant = CapabilityGrant(
        tenant_id=tenant,
        principal_id="p1",
        roles=["analyst"],
        tier="pro",
        capabilities=list(caps),
        issued_at=now_utc().isoformat(),
        expires_at=(now_utc() + timedelta(hours=hours)).isoformat(),
    ).sign(priv)
    return encode_grant(grant)


def _seed(factory, tenant: str, target: str = "https://example.com/x", track: str = "sast") -> str:
    from runner.repository import create_scan

    with factory() as s:
        return create_scan(s, tenant, target=target, track=track).id


def test_healthz(runner):
    client, _ = runner
    resp = client.get("/v1/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_scans_requires_grant(runner):
    client, _ = runner
    assert client.get("/v1/scans").status_code == 401
    assert client.get("/v1/scans", headers={"Authorization": "Bearer garbage"}).status_code == 401


def test_scans_rejects_wrong_key(runner):
    # A grant signed by a different keypair does not verify under the Runner's public key.
    client, _ = runner
    other_priv, _ = generate_keypair()
    hdr = {"Authorization": f"Bearer {_bearer(priv=other_priv)}"}
    assert client.get("/v1/scans", headers=hdr).status_code == 401


def test_scans_rejects_expired(runner):
    client, _ = runner
    hdr = {"Authorization": f"Bearer {_bearer(hours=-1.0)}"}
    assert client.get("/v1/scans", headers=hdr).status_code == 401


def test_scans_requires_capability(runner):
    # A validly signed, unexpired grant that lacks control_plane_read is refused 403.
    client, _ = runner
    hdr = {"Authorization": f"Bearer {_bearer(caps=())}"}
    assert client.get("/v1/scans", headers=hdr).status_code == 403


def test_scans_tenant_isolation(runner):
    # A grant for tenant A sees only tenant A's scans over the API, never tenant B's.
    client, factory = runner
    a_id = _seed(factory, "t-a", target="https://a.example/x")
    _seed(factory, "t-b", target="https://b.example/x")

    body = client.get(
        "/v1/scans", headers={"Authorization": f"Bearer {_bearer(tenant='t-a')}"}
    ).json()
    assert {s["id"] for s in body["scans"]} == {a_id}
    assert {s["target"] for s in body["scans"]} == {"https://a.example/x"}


def test_repository_list_is_tenant_scoped(runner):
    from runner.repository import list_scans

    _client, factory = runner
    _seed(factory, "t-a")
    _seed(factory, "t-b")
    with factory() as s:
        assert [sc.tenant_id for sc in list_scans(s, "t-a")] == ["t-a"]
        assert [sc.tenant_id for sc in list_scans(s, "t-b")] == ["t-b"]


def _create_engagement(client, tenant="t-a", domains=("example.com",)):
    hdr = {"Authorization": f"Bearer {_bearer(tenant=tenant, caps=_SCAN_CAPS)}"}
    body = {"authorized_by": "op@acme", "scope": {"allowlist": {"domains": list(domains)}}}
    return client.post("/v1/engagements", json=body, headers=hdr), hdr


def test_engagement_create_get_close(runner):
    client, _ = runner
    created, hdr = _create_engagement(client)
    assert created.status_code == 200 and created.json()["open"] is True
    eid = created.json()["id"]

    got = client.get(f"/v1/engagements/{eid}", headers=hdr).json()
    assert got["valid"] is True and got["open"] is True  # open, unexpired, signed

    closed = client.post(f"/v1/engagements/{eid}/close", headers=hdr)
    assert closed.status_code == 200 and closed.json()["open"] is False

    after = client.get(f"/v1/engagements/{eid}", headers=hdr).json()
    assert after["open"] is False and after["valid"] is False  # closed -> invalid


def test_engagement_create_requires_scan_capability(runner):
    client, _ = runner
    # A read-only grant lacks control_plane_scan.
    hdr = {"Authorization": f"Bearer {_bearer(caps=('control_plane_read',))}"}
    resp = client.post(
        "/v1/engagements", json={"authorized_by": "v", "scope": {"allowlist": {}}}, headers=hdr
    )
    assert resp.status_code == 403


def test_engagement_tenant_isolation(runner):
    client, _ = runner
    created, _ = _create_engagement(client, tenant="t-a")
    eid = created.json()["id"]
    b = {"Authorization": f"Bearer {_bearer(tenant='t-b', caps=_SCAN_CAPS)}"}
    a = {"Authorization": f"Bearer {_bearer(tenant='t-a', caps=_SCAN_CAPS)}"}
    # Tenant B cannot see or close tenant A's engagement.
    assert client.get(f"/v1/engagements/{eid}", headers=b).status_code == 404
    assert client.post(f"/v1/engagements/{eid}/close", headers=b).status_code == 404
    assert client.get(f"/v1/engagements/{eid}", headers=a).status_code == 200


def test_consume_token_durable_single_use(runner):
    from runner.repository import consume_token

    _client, factory = runner
    with factory() as s:
        assert consume_token(s, "t-a", "nonce-1") is True
        assert consume_token(s, "t-a", "nonce-1") is False  # replay refused, durable
        assert consume_token(s, "t-b", "nonce-1") is True  # same nonce, other tenant, independent


def test_scan_runs_and_stores_findings(runner):
    client, _ = runner
    created, hdr = _create_engagement(client, domains=("example.com",))
    eid = created.json()["id"]
    resp = client.post(
        "/v1/scans",
        json={"engagement_id": eid, "target": "https://example.com/x", "track": "sast"},
        headers=hdr,
    )
    assert resp.status_code == 200
    sid = resp.json()["id"]
    # The inline executor ran the scan synchronously, so findings are already stored.
    got = client.get(f"/v1/scans/{sid}", headers=hdr).json()
    assert got["status"] == "completed"
    assert {f["finding_id"] for f in got["findings"]} == {"f1"}


def test_scan_requires_scan_capability(runner):
    client, _ = runner
    created, hdr = _create_engagement(client)
    eid = created.json()["id"]
    ro = {"Authorization": f"Bearer {_bearer(caps=('control_plane_read',))}"}
    resp = client.post(
        "/v1/scans",
        json={"engagement_id": eid, "target": "https://example.com/x", "track": "sast"},
        headers=ro,
    )
    assert resp.status_code == 403


def test_scan_out_of_scope_refused(runner):
    client, _ = runner
    created, hdr = _create_engagement(client, domains=("example.com",))
    eid = created.json()["id"]
    resp = client.post(
        "/v1/scans",
        json={"engagement_id": eid, "target": "https://evil.test/x", "track": "sast"},
        headers=hdr,
    )
    assert resp.status_code == 403


def test_scan_under_closed_engagement_refused(runner):
    client, _ = runner
    created, hdr = _create_engagement(client)
    eid = created.json()["id"]
    client.post(f"/v1/engagements/{eid}/close", headers=hdr)
    resp = client.post(
        "/v1/scans",
        json={"engagement_id": eid, "target": "https://example.com/x", "track": "sast"},
        headers=hdr,
    )
    assert resp.status_code == 403


def test_scan_tenant_isolation(runner):
    client, _ = runner
    created, _ = _create_engagement(client, tenant="t-a")
    eid = created.json()["id"]
    b = {"Authorization": f"Bearer {_bearer(tenant='t-b', caps=_SCAN_CAPS)}"}
    resp = client.post(
        "/v1/scans",
        json={"engagement_id": eid, "target": "https://example.com/x", "track": "sast"},
        headers=b,
    )
    assert resp.status_code == 404  # engagement belongs to tenant A


def test_scan_unsupported_track(runner):
    client, _ = runner
    created, hdr = _create_engagement(client)
    eid = created.json()["id"]
    resp = client.post(
        "/v1/scans",
        json={"engagement_id": eid, "target": "https://example.com/x", "track": "web"},
        headers=hdr,
    )
    assert resp.status_code == 400  # dynamic/offensive tracks are not yet server-side


def _scan_body(eid):
    return {"engagement_id": eid, "target": "https://example.com/x", "track": "sast"}


def test_per_tenant_kill_blocks_and_resets(runner):
    client, _ = runner
    created, hdr = _create_engagement(client)
    body = _scan_body(created.json()["id"])
    assert client.post("/v1/kill", json={}, headers=hdr).json()["killed"] is True
    assert client.post("/v1/scans", json=body, headers=hdr).status_code == 503
    assert client.post("/v1/kill", json={"reset": True}, headers=hdr).json()["killed"] is False
    assert client.post("/v1/scans", json=body, headers=hdr).status_code == 200


def test_per_tenant_kill_is_isolated(runner):
    client, _ = runner
    a_created, a_hdr = _create_engagement(client, tenant="t-a")
    b_created, b_hdr = _create_engagement(client, tenant="t-b")
    client.post("/v1/kill", json={}, headers=a_hdr)  # kill tenant A only
    assert client.post("/v1/scans", json=_scan_body(a_created.json()["id"]), headers=a_hdr).status_code == 503
    assert client.post("/v1/scans", json=_scan_body(b_created.json()["id"]), headers=b_hdr).status_code == 200


def test_kill_requires_scan_capability(runner):
    client, _ = runner
    ro = {"Authorization": f"Bearer {_bearer(caps=('control_plane_read',))}"}
    assert client.post("/v1/kill", json={}, headers=ro).status_code == 403


def test_global_kill_blocks_all_tenants(runner):
    client, _ = runner
    a_created, a_hdr = _create_engagement(client, tenant="t-a")
    b_created, b_hdr = _create_engagement(client, tenant="t-b")
    pk = {"X-Platform-Key": PLATFORM_KEY.decode()}
    assert client.post("/v1/admin/kill", json={}, headers=pk).json()["killed"] is True
    assert client.post("/v1/scans", json=_scan_body(a_created.json()["id"]), headers=a_hdr).status_code == 503
    assert client.post("/v1/scans", json=_scan_body(b_created.json()["id"]), headers=b_hdr).status_code == 503
    client.post("/v1/admin/kill", json={"reset": True}, headers=pk)
    assert client.post("/v1/scans", json=_scan_body(a_created.json()["id"]), headers=a_hdr).status_code == 200


def test_global_kill_requires_platform_key(runner):
    client, _ = runner
    assert client.post("/v1/admin/kill", json={}).status_code == 401
    assert client.post("/v1/admin/kill", json={}, headers={"X-Platform-Key": "wrong"}).status_code == 401


def test_run_scan_marks_killed_scan(runner):
    from runner.repository import engage_kill, get_scan
    from runner.worker import run_scan

    _client, factory = runner
    sid = _seed(factory, "t-a", target="https://example.com/x")  # a queued scan
    with factory() as s:
        engage_kill(s, "t-a")
    run_scan(factory, "unused", RESULT_KEY, [_FakeScanAdapter()], "t-a", sid, "https://example.com/x")
    with factory() as s:
        scan = get_scan(s, "t-a", sid)
        assert scan is not None and scan.status == "killed"
