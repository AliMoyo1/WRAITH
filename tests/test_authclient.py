"""Tests for the login client, driven against an in-process authority app."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

KEY = b"authclient-entitlement-key"
MFA_KEY = Fernet.generate_key()


@pytest.fixture
def authed(tmp_path):
    from fastapi.testclient import TestClient

    from authority import create_app
    from authority.db import create_all, make_engine, make_session_factory
    from client import AuthClient

    engine = make_engine(f"sqlite:///{tmp_path / 'authority.db'}")
    create_all(engine)
    factory = make_session_factory(engine)
    app = create_app(session_factory=factory, entitlement_key=KEY, mfa_key=MFA_KEY)
    http = TestClient(app)
    return AuthClient("http://authority", http_client=http), factory, http


def _seed(factory, tier, roles):
    from authority.repository import create_principal, create_tenant

    with factory() as s:
        tenant = create_tenant(s, "Acme", slug="acme", tier=tier)
        create_principal(s, tenant.id, "op@acme.example", "s3cret", roles=list(roles))


def _enroll_mfa(http):
    import pyotp

    creds = {"tenant": "acme", "email": "op@acme.example", "password": "s3cret"}
    secret = http.post("/v1/mfa/enroll", json=creds).json()["secret"]
    http.post("/v1/mfa/confirm", json={**creds, "code": pyotp.TOTP(secret).now()})
    return secret


def test_login_and_me(authed):
    client, factory, _ = authed
    _seed(factory, "pro", ("analyst",))
    session = client.login("acme", "op@acme.example", "s3cret")
    assert session["grant"] and session["refresh_token"]
    assert client.me(session["grant"])["tier"] == "pro"


def test_login_requires_mfa_code(authed):
    from client import AuthError

    client, factory, http = authed
    _seed(factory, "enterprise", ("operator",))
    _enroll_mfa(http)
    with pytest.raises(AuthError, match="MFA"):
        client.login("acme", "op@acme.example", "s3cret")  # no code


def test_login_with_mfa_code(authed):
    import pyotp

    client, factory, http = authed
    _seed(factory, "enterprise", ("operator",))
    secret = _enroll_mfa(http)
    session = client.login("acme", "op@acme.example", "s3cret", code=pyotp.TOTP(secret).now())
    assert "redteam_exploit" in client.me(session["grant"])["capabilities"]


def test_refresh_and_session_roundtrip(authed, tmp_path):
    from client import grant_expired, load_session, refreshed, save_session

    client, factory, _ = authed
    _seed(factory, "pro", ("analyst",))
    session = client.login("acme", "op@acme.example", "s3cret")

    path = tmp_path / "session.json"
    save_session(path, session)
    assert load_session(path)["grant"] == session["grant"]

    # Force expiry, then refresh through the helper.
    session["expires_at"] = "2000-01-01T00:00:00+00:00"
    assert grant_expired(session)
    rotated = refreshed(client, session)
    assert rotated["grant"] and rotated["refresh_token"] != session["refresh_token"]


def test_load_session_missing_is_none(tmp_path):
    from client import load_session

    assert load_session(tmp_path / "nope.json") is None
