"""Tests for the authority service: health, tenant isolation, login, and /me."""

from __future__ import annotations

import pytest

KEY = b"authority-test-entitlement-key"


@pytest.fixture
def app_client(tmp_path):
    from fastapi.testclient import TestClient

    from authority import create_app
    from authority.db import create_all, make_engine, make_session_factory

    engine = make_engine(f"sqlite:///{tmp_path / 'authority.db'}")
    create_all(engine)
    factory = make_session_factory(engine)
    app = create_app(session_factory=factory, entitlement_key=KEY)
    return TestClient(app), factory


@pytest.fixture
def session(tmp_path):
    from authority.db import create_all, make_engine, make_session_factory

    engine = make_engine(f"sqlite:///{tmp_path / 'authority.db'}")
    create_all(engine)
    factory = make_session_factory(engine)
    s = factory()
    try:
        yield s
    finally:
        s.close()


def _seed(factory, tier="enterprise", roles=("operator",)):
    from authority.repository import create_principal, create_tenant

    with factory() as s:
        tenant = create_tenant(s, "Acme", slug="acme", tier=tier)
        create_principal(s, tenant.id, "op@acme.example", "s3cret", roles=list(roles))


def test_healthz(app_client):
    client, _ = app_client
    resp = client.get("/v1/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_tenant_isolation(session):
    from authority.repository import create_principal, create_tenant, list_principals

    a = create_tenant(session, "Tenant A", slug="tenant-a")
    b = create_tenant(session, "Tenant B", slug="tenant-b")
    create_principal(session, a.id, "alice@a.example", "pw-a", roles=["analyst"])
    create_principal(session, b.id, "bob@b.example", "pw-b", roles=["viewer"])

    assert [p.email for p in list_principals(session, a.id)] == ["alice@a.example"]
    assert [p.email for p in list_principals(session, b.id)] == ["bob@b.example"]


def test_login_success_and_me(app_client):
    client, factory = app_client
    _seed(factory, tier="enterprise", roles=("operator",))

    resp = client.post(
        "/v1/auth/login",
        json={"tenant": "acme", "email": "op@acme.example", "password": "s3cret"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["grant"] and body["refresh_token"]

    me = client.get("/v1/me", headers={"Authorization": f"Bearer {body['grant']}"})
    assert me.status_code == 200
    data = me.json()
    assert data["tier"] == "enterprise"
    assert "operator" in data["roles"]
    # Enterprise + Operator earns the exploit capability class.
    assert "redteam_exploit" in data["capabilities"]


def test_login_wrong_password(app_client):
    client, factory = app_client
    _seed(factory)
    resp = client.post(
        "/v1/auth/login",
        json={"tenant": "acme", "email": "op@acme.example", "password": "wrong"},
    )
    assert resp.status_code == 401


def test_login_unknown_tenant(app_client):
    client, _ = app_client
    resp = client.post(
        "/v1/auth/login",
        json={"tenant": "nope", "email": "x@y.example", "password": "z"},
    )
    assert resp.status_code == 401


def test_me_requires_valid_grant(app_client):
    client, _ = app_client
    assert client.get("/v1/me").status_code == 401
    assert client.get("/v1/me", headers={"Authorization": "Bearer garbage"}).status_code == 401


def test_capabilities_follow_the_matrix(app_client):
    # A Pro-tier Analyst probes but must never receive the exploit class.
    client, factory = app_client
    _seed(factory, tier="pro", roles=("analyst",))
    resp = client.post(
        "/v1/auth/login",
        json={"tenant": "acme", "email": "op@acme.example", "password": "s3cret"},
    )
    grant = resp.json()["grant"]
    caps = client.get("/v1/me", headers={"Authorization": f"Bearer {grant}"}).json()["capabilities"]
    assert "redteam_probe" in caps
    assert "redteam_exploit" not in caps
