"""Tests for the Runner skeleton: health, public-key grant verification, the
capability-class check, and tenant isolation.

Grants are built and signed here with a test private key; the Runner is given only
the matching public key, mirroring production where the signing secret never
reaches the Runner.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from entitlement import CapabilityGrant, encode_grant, generate_keypair, now_utc

PRIV, PUB = generate_keypair()


@pytest.fixture
def runner(tmp_path):
    from fastapi.testclient import TestClient

    from runner import create_app
    from runner.db import create_all, make_engine, make_session_factory

    engine = make_engine(f"sqlite:///{tmp_path / 'runner.db'}")
    create_all(engine)
    factory = make_session_factory(engine)
    app = create_app(session_factory=factory, entitlement_public_key=PUB)
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
