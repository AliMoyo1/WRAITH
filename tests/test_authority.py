"""Tests for the authority service: health, isolation, login, MFA, and /me."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from entitlement import generate_keypair

PRIV = generate_keypair()[0]
MFA_KEY = Fernet.generate_key()


@pytest.fixture
def app_client(tmp_path):
    from fastapi.testclient import TestClient

    from authority import create_app
    from authority.db import create_all, make_engine, make_session_factory

    engine = make_engine(f"sqlite:///{tmp_path / 'authority.db'}")
    create_all(engine)
    factory = make_session_factory(engine)
    app = create_app(session_factory=factory, entitlement_private_key=PRIV, mfa_key=MFA_KEY)
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


def _operator_grant(client):
    # Enroll and confirm MFA, then log in and verify to obtain an Operator grant.
    secret = client.post("/v1/mfa/enroll", json=_CREDS).json()["secret"]
    client.post("/v1/mfa/confirm", json={**_CREDS, "code": _totp_now(secret)})
    challenge = client.post("/v1/auth/login", json=_CREDS).json()["challenge"]
    return client.post(
        "/v1/auth/mfa/verify", json={"challenge": challenge, "code": _totp_now(secret)}
    ).json()["grant"]


def test_api_key_create_exchange_and_revoke(app_client):
    client, factory = app_client
    _seed(factory, tier="pro", roles=("analyst",))
    grant = client.post("/v1/auth/login", json=_CREDS).json()["grant"]
    hdr = {"Authorization": f"Bearer {grant}"}

    created = client.post("/v1/api-keys", json={"name": "ci"}, headers=hdr)
    assert created.status_code == 200
    raw = created.json()["api_key"]
    key_id = created.json()["id"]

    listed = client.get("/v1/api-keys", headers=hdr).json()["api_keys"]
    assert any(k["id"] == key_id and k["name"] == "ci" for k in listed)

    token = client.post("/v1/auth/token", json={"api_key": raw})
    assert token.status_code == 200
    exchanged = {"Authorization": f"Bearer {token.json()['grant']}"}
    assert client.get("/v1/me", headers=exchanged).status_code == 200

    assert client.delete(f"/v1/api-keys/{key_id}", headers=hdr).status_code == 200
    assert client.post("/v1/auth/token", json={"api_key": raw}).status_code == 401


def test_api_key_grant_capped_below_operator(app_client):
    client, factory = app_client
    _seed(factory, tier="enterprise", roles=("operator",))
    op_grant = _operator_grant(client)
    hdr = {"Authorization": f"Bearer {op_grant}"}
    op_caps = client.get("/v1/me", headers=hdr).json()["capabilities"]
    assert "redteam_exploit" in op_caps
    assert "control_plane_engage" in op_caps  # an interactive Operator can author engagements

    raw = client.post("/v1/api-keys", json={"name": "bot"}, headers=hdr).json()["api_key"]
    key_grant = client.post("/v1/auth/token", json={"api_key": raw}).json()["grant"]
    key_caps = client.get(
        "/v1/me", headers={"Authorization": f"Bearer {key_grant}"}
    ).json()["capabilities"]
    assert "redteam_probe" in key_caps  # non-elevated classes remain
    assert "control_plane_scan" in key_caps  # automation can still run scans
    assert "redteam_exploit" not in key_caps  # capped below Operator
    assert "redteam_post_exploit" not in key_caps
    assert "control_plane_engage" not in key_caps  # automation cannot self-author engagements


def test_auth_token_rejects_bad_key(app_client):
    client, factory = app_client
    _seed(factory, tier="pro", roles=("analyst",))
    assert client.post("/v1/auth/token", json={"api_key": "wak_nope"}).status_code == 401


def test_api_keys_require_auth(app_client):
    client, _ = app_client
    assert client.post("/v1/api-keys", json={"name": "x"}).status_code == 401
    assert client.get("/v1/api-keys").status_code == 401


def test_admin_manage_principals_and_tier(app_client):
    client, factory = app_client
    _seed(factory, tier="enterprise", roles=("admin",))  # the acting admin (MFA required)
    hdr = {"Authorization": f"Bearer {_operator_grant(client)}"}

    created = client.post(
        "/v1/admin/principals",
        json={"email": "new@acme.example", "password": "pw123456", "roles": ["analyst"]},
        headers=hdr,
    )
    assert created.status_code == 200
    new_id = created.json()["id"]

    listed = client.get("/v1/admin/principals", headers=hdr).json()["principals"]
    assert any(p["id"] == new_id and "analyst" in p["roles"] for p in listed)

    updated = client.patch(
        f"/v1/admin/principals/{new_id}",
        json={"roles": ["viewer"], "status": "disabled"},
        headers=hdr,
    )
    assert updated.status_code == 200
    assert updated.json()["roles"] == ["viewer"]
    assert updated.json()["status"] == "disabled"

    tier = client.patch("/v1/admin/tenant", json={"tier": "pro"}, headers=hdr)
    assert tier.status_code == 200
    assert tier.json()["tier"] == "pro"


def test_admin_requires_admin_class(app_client):
    # An analyst grant cannot reach the admin endpoints.
    client, factory = app_client
    _seed(factory, tier="pro", roles=("analyst",))
    grant = client.post("/v1/auth/login", json=_CREDS).json()["grant"]
    hdr = {"Authorization": f"Bearer {grant}"}
    assert client.get("/v1/admin/principals", headers=hdr).status_code == 403
    assert client.patch("/v1/admin/tenant", json={"tier": "pro"}, headers=hdr).status_code == 403


def test_admin_rejects_unknown_role(app_client):
    client, factory = app_client
    _seed(factory, tier="enterprise", roles=("admin",))
    hdr = {"Authorization": f"Bearer {_operator_grant(client)}"}
    resp = client.post(
        "/v1/admin/principals",
        json={"email": "x@acme.example", "password": "pw123456", "roles": ["wizard"]},
        headers=hdr,
    )
    assert resp.status_code == 400


def test_admin_created_principal_can_login(app_client):
    client, factory = app_client
    _seed(factory, tier="pro", roles=("admin",))
    hdr = {"Authorization": f"Bearer {_operator_grant(client)}"}
    client.post(
        "/v1/admin/principals",
        json={"email": "viewer@acme.example", "password": "pw123456", "roles": ["viewer"]},
        headers=hdr,
    )
    login = client.post(
        "/v1/auth/login",
        json={"tenant": "acme", "email": "viewer@acme.example", "password": "pw123456"},
    )
    assert login.status_code == 200
    assert login.json()["grant"]


def test_revoke_refresh_if_active_is_one_shot(session):
    # The atomic conditional revoke succeeds exactly once; a concurrent second
    # rotation of the same token loses and is denied. (Audit High: refresh race.)
    from authority.repository import (
        create_principal,
        create_tenant,
        revoke_refresh_if_active,
        store_refresh_token,
    )

    tenant = create_tenant(session, "Acme", slug="acme")
    principal = create_principal(session, tenant.id, "op@acme.example", "pw", roles=["analyst"])
    token = store_refresh_token(session, principal.id, "hash-1")

    assert revoke_refresh_if_active(session, token.id) is True
    assert revoke_refresh_if_active(session, token.id) is False


def test_disabled_tenant_blocks_auth(app_client):
    # Tenant.status is enforced: a disabled tenant cannot log in, and an already
    # issued grant and refresh token stop working. (Audit High: disabled tenants.)
    from authority.repository import get_tenant_by_slug

    client, factory = app_client
    _seed(factory, tier="pro", roles=("analyst",))
    login = client.post("/v1/auth/login", json=_CREDS).json()
    grant, refresh = login["grant"], login["refresh_token"]

    with factory() as s:
        get_tenant_by_slug(s, "acme").status = "disabled"
        s.commit()

    assert client.post("/v1/auth/login", json=_CREDS).status_code == 403
    assert client.get("/v1/me", headers={"Authorization": f"Bearer {grant}"}).status_code == 403
    assert client.post("/v1/auth/refresh", json={"refresh_token": refresh}).status_code == 403


def test_reenroll_requires_current_code(app_client):
    # Audit Critical: a stolen password alone must not be able to replace a
    # confirmed MFA factor. Re-enrollment requires a current code; first-time
    # enrollment stays password-only.
    client, factory = app_client
    _seed(factory, tier="enterprise", roles=("operator",))
    secret = client.post("/v1/mfa/enroll", json=_CREDS).json()["secret"]
    client.post("/v1/mfa/confirm", json={**_CREDS, "code": _totp_now(secret)})

    # Attacker with only the password cannot re-enroll.
    assert client.post("/v1/mfa/enroll", json=_CREDS).status_code == 403
    assert client.post("/v1/mfa/enroll", json={**_CREDS, "code": "000000"}).status_code == 403

    # The legitimate holder, proving the current factor, can rotate to a new secret.
    resp = client.post("/v1/mfa/enroll", json={**_CREDS, "code": _totp_now(secret)})
    assert resp.status_code == 200
    assert resp.json()["secret"] != secret


def test_mfa_challenge_is_single_use(app_client):
    # Audit High: a challenge (and code) must not mint two sessions.
    client, factory = app_client
    _seed(factory, tier="enterprise", roles=("operator",))
    secret = client.post("/v1/mfa/enroll", json=_CREDS).json()["secret"]
    client.post("/v1/mfa/confirm", json={**_CREDS, "code": _totp_now(secret)})
    challenge = client.post("/v1/auth/login", json=_CREDS).json()["challenge"]
    code = _totp_now(secret)

    assert client.post(
        "/v1/auth/mfa/verify", json={"challenge": challenge, "code": code}
    ).status_code == 200
    # Replaying the same challenge is refused.
    assert client.post(
        "/v1/auth/mfa/verify", json={"challenge": challenge, "code": code}
    ).status_code == 401


def test_api_key_grant_cannot_mint_keys(app_client):
    # Audit High: an API-key-derived grant must not mint or revoke API keys.
    client, factory = app_client
    _seed(factory, tier="pro", roles=("analyst",))
    grant = client.post("/v1/auth/login", json=_CREDS).json()["grant"]
    hdr = {"Authorization": f"Bearer {grant}"}
    raw = client.post("/v1/api-keys", json={"name": "ci"}, headers=hdr).json()["api_key"]
    key_grant = client.post("/v1/auth/token", json={"api_key": raw}).json()["grant"]
    kh = {"Authorization": f"Bearer {key_grant}"}

    assert client.post("/v1/api-keys", json={"name": "child"}, headers=kh).status_code == 403
    assert client.delete("/v1/api-keys/anything", headers=kh).status_code == 403
    # The marker gates by issuance context, not role: interactive has it, key does not.
    assert "api_key_manage" in client.get("/v1/me", headers=hdr).json()["capabilities"]
    assert "api_key_manage" not in client.get("/v1/me", headers=kh).json()["capabilities"]


def test_logout_revokes_refresh(app_client):
    # Audit High: logout must revoke server-side, not only delete the local file.
    client, factory = app_client
    _seed(factory, tier="pro", roles=("analyst",))
    refresh = client.post("/v1/auth/login", json=_CREDS).json()["refresh_token"]

    assert client.post("/v1/auth/logout", json={"refresh_token": refresh}).status_code == 200
    assert client.post("/v1/auth/refresh", json={"refresh_token": refresh}).status_code == 401
    # Idempotent and not a token oracle: an unknown token still returns 200.
    assert client.post("/v1/auth/logout", json={"refresh_token": "nope"}).status_code == 200
