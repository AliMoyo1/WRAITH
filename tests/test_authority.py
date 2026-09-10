"""Tests for the authority service: health, isolation, login, MFA, and /me."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

KEY = b"authority-test-entitlement-key"
MFA_KEY = Fernet.generate_key()


@pytest.fixture
def app_client(tmp_path):
    from fastapi.testclient import TestClient

    from authority import create_app
    from authority.db import create_all, make_engine, make_session_factory

    engine = make_engine(f"sqlite:///{tmp_path / 'authority.db'}")
    create_all(engine)
    factory = make_session_factory(engine)
    app = create_app(session_factory=factory, entitlement_key=KEY, mfa_key=MFA_KEY)
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


def _totp_now(secret):
    import pyotp

    return pyotp.TOTP(secret).now()


_CREDS = {"tenant": "acme", "email": "op@acme.example", "password": "s3cret"}


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


def test_login_direct_for_non_elevated(app_client):
    # A Pro Analyst is not MFA-required, so login returns a grant directly.
    client, factory = app_client
    _seed(factory, tier="pro", roles=("analyst",))
    resp = client.post("/v1/auth/login", json=_CREDS)
    assert resp.status_code == 200
    body = resp.json()
    assert body["grant"] and body["refresh_token"]

    caps = client.get(
        "/v1/me", headers={"Authorization": f"Bearer {body['grant']}"}
    ).json()["capabilities"]
    assert "redteam_probe" in caps
    assert "redteam_exploit" not in caps


def test_login_wrong_password(app_client):
    client, factory = app_client
    _seed(factory)
    resp = client.post("/v1/auth/login", json={**_CREDS, "password": "wrong"})
    assert resp.status_code == 401


def test_login_unknown_tenant(app_client):
    client, _ = app_client
    resp = client.post(
        "/v1/auth/login", json={"tenant": "nope", "email": "x@y.example", "password": "z"}
    )
    assert resp.status_code == 401


def test_me_requires_valid_grant(app_client):
    client, _ = app_client
    assert client.get("/v1/me").status_code == 401
    assert client.get("/v1/me", headers={"Authorization": "Bearer garbage"}).status_code == 401


def test_operator_login_requires_mfa(app_client):
    # Operator is MFA-required; without enrollment the login is refused.
    client, factory = app_client
    _seed(factory, tier="enterprise", roles=("operator",))
    resp = client.post("/v1/auth/login", json=_CREDS)
    assert resp.status_code == 403


def test_mfa_enroll_confirm_and_login(app_client):
    client, factory = app_client
    _seed(factory, tier="enterprise", roles=("operator",))

    secret = client.post("/v1/mfa/enroll", json=_CREDS).json()["secret"]
    assert client.post("/v1/mfa/confirm", json={**_CREDS, "code": _totp_now(secret)}).status_code == 200

    # Login now returns a challenge, not a grant.
    login = client.post("/v1/auth/login", json=_CREDS).json()
    assert login.get("mfa_required") is True
    assert "grant" not in login

    verify = client.post(
        "/v1/auth/mfa/verify", json={"challenge": login["challenge"], "code": _totp_now(secret)}
    )
    assert verify.status_code == 200
    grant = verify.json()["grant"]

    caps = client.get(
        "/v1/me", headers={"Authorization": f"Bearer {grant}"}
    ).json()["capabilities"]
    assert "redteam_exploit" in caps  # Enterprise + Operator, after MFA


def test_mfa_confirm_rejects_wrong_code(app_client):
    client, factory = app_client
    _seed(factory, tier="enterprise", roles=("operator",))
    client.post("/v1/mfa/enroll", json=_CREDS)
    assert client.post("/v1/mfa/confirm", json={**_CREDS, "code": "000000"}).status_code == 401


def test_mfa_verify_rejects_wrong_code(app_client):
    client, factory = app_client
    _seed(factory, tier="enterprise", roles=("operator",))
    secret = client.post("/v1/mfa/enroll", json=_CREDS).json()["secret"]
    client.post("/v1/mfa/confirm", json={**_CREDS, "code": _totp_now(secret)})
    challenge = client.post("/v1/auth/login", json=_CREDS).json()["challenge"]
    resp = client.post("/v1/auth/mfa/verify", json={"challenge": challenge, "code": "000000"})
    assert resp.status_code == 401


def test_refresh_issues_new_grant_and_rotates(app_client):
    client, factory = app_client
    _seed(factory, tier="pro", roles=("analyst",))
    login = client.post("/v1/auth/login", json=_CREDS).json()

    r1 = client.post("/v1/auth/refresh", json={"refresh_token": login["refresh_token"]})
    assert r1.status_code == 200
    new = r1.json()
    assert new["grant"] and new["refresh_token"] != login["refresh_token"]
    assert client.get("/v1/me", headers={"Authorization": f"Bearer {new['grant']}"}).status_code == 200

    # The presented token is now revoked; the rotated one still works.
    old = client.post("/v1/auth/refresh", json={"refresh_token": login["refresh_token"]})
    assert old.status_code == 401
    again = client.post("/v1/auth/refresh", json={"refresh_token": new["refresh_token"]})
    assert again.status_code == 200


def test_refresh_reresolves_tier(app_client):
    from authority.repository import get_tenant_by_slug

    client, factory = app_client
    _seed(factory, tier="community", roles=("analyst",))
    login = client.post("/v1/auth/login", json=_CREDS).json()
    caps1 = client.get(
        "/v1/me", headers={"Authorization": f"Bearer {login['grant']}"}
    ).json()["capabilities"]
    assert "redteam_recon" not in caps1  # community analyst has no red team classes

    with factory() as s:
        tenant = get_tenant_by_slug(s, "acme")
        tenant.tier = "pro"
        s.commit()

    refreshed = client.post(
        "/v1/auth/refresh", json={"refresh_token": login["refresh_token"]}
    ).json()
    caps2 = client.get(
        "/v1/me", headers={"Authorization": f"Bearer {refreshed['grant']}"}
    ).json()["capabilities"]
    assert "redteam_recon" in caps2  # re-resolved at the upgraded tier


def test_refresh_rejects_garbage(app_client):
    client, factory = app_client
    _seed(factory, tier="pro", roles=("analyst",))
    assert client.post("/v1/auth/refresh", json={"refresh_token": "nope"}).status_code == 401
