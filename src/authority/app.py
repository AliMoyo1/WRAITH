"""FastAPI application for the WRAITH authority service.

Sub-phase 3 adds TOTP MFA. Enrollment and confirmation are password-authenticated
bootstrap steps. At login, a principal holding the Operator or Admin role must
have confirmed MFA: if MFA is confirmed, login returns a short-lived challenge
instead of a grant, and POST /v1/auth/mfa/verify exchanges a valid code for the
grant. A non-elevated principal without MFA still receives a grant directly.
"""

from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session, sessionmaker

from entitlement import CapabilityGrant

from . import repository
from .config import (
    database_url,
)
from .config import (
    entitlement_key as _default_entitlement_key,
)
from .config import (
    mfa_key as _default_mfa_key,
)
from .db import create_all, make_engine, make_session_factory
from .grants import decode_grant, encode_grant, issue_grant, new_refresh_token
from .mfa import (
    decrypt_secret,
    encrypt_secret,
    generate_secret,
    make_challenge,
    provisioning_uri,
    read_challenge,
    verify_code,
)
from .models import Principal, Tenant
from .security import verify_password

_MFA_ROLES = frozenset({"operator", "admin"})


class LoginRequest(BaseModel):
    tenant: str
    email: str
    password: str


class MfaEnrollRequest(BaseModel):
    tenant: str
    email: str
    password: str


class MfaConfirmRequest(BaseModel):
    tenant: str
    email: str
    password: str
    code: str


class MfaVerifyRequest(BaseModel):
    challenge: str
    code: str


def _mfa_required(roles: list[str]) -> bool:
    return any(role in _MFA_ROLES for role in roles)


def _authenticate(
    session: Session, tenant_slug: str, email: str, password: str
) -> tuple[Principal, Tenant]:
    tenant = repository.get_tenant_by_slug(session, tenant_slug)
    principal = (
        repository.get_principal_by_email(session, tenant.id, email)
        if tenant is not None
        else None
    )
    if (
        tenant is None
        or principal is None
        or principal.status != "active"
        or not verify_password(password, principal.password_hash)
    ):
        # One message for every failure mode: no account enumeration.
        raise HTTPException(status_code=401, detail="invalid credentials")
    return principal, tenant


def _issue_login_response(
    session: Session, key: bytes, principal: Principal, tenant: Tenant, roles: list[str]
) -> dict[str, object]:
    grant = issue_grant(key, tenant.id, principal.id, roles, tenant.tier)
    raw_refresh, refresh_hash = new_refresh_token()
    repository.store_refresh_token(session, principal.id, refresh_hash)
    payload: dict[str, object] = {
        "grant": encode_grant(grant),
        "refresh_token": raw_refresh,
        "expires_at": grant.expires_at,
    }
    return payload


def _grant_from_header(authorization: str, key: bytes) -> CapabilityGrant:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer grant")
    token = authorization[len("bearer "):].strip()
    try:
        grant = decode_grant(token)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="malformed grant") from exc
    if not grant.verify(key) or grant.is_expired():
        raise HTTPException(status_code=401, detail="invalid or expired grant")
    return grant


def create_app(
    session_factory: sessionmaker[Session] | None = None,
    entitlement_key: bytes | None = None,
    mfa_key: bytes | None = None,
) -> FastAPI:
    if session_factory is None:
        engine = make_engine(database_url())
        create_all(engine)
        session_factory = make_session_factory(engine)
    key = entitlement_key if entitlement_key is not None else _default_entitlement_key()
    mkey = mfa_key if mfa_key is not None else _default_mfa_key()

    app = FastAPI(title="WRAITH Authority", version="0.3.0")
    app.state.session_factory = session_factory

    @app.get("/v1/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/auth/login")
    def login(body: LoginRequest) -> dict[str, object]:
        with session_factory() as session:
            principal, tenant = _authenticate(session, body.tenant, body.email, body.password)
            roles = repository.get_roles(session, principal.id)
            cred = repository.get_mfa(session, principal.id)
            confirmed = cred is not None and cred.confirmed_at is not None
            if _mfa_required(roles) and not confirmed:
                raise HTTPException(status_code=403, detail="mfa enrollment required")
            if confirmed:
                challenge = make_challenge(mkey, principal.id, tenant.id)
                return {"mfa_required": True, "challenge": challenge}
            return _issue_login_response(session, key, principal, tenant, roles)

    @app.post("/v1/auth/mfa/verify")
    def mfa_verify(body: MfaVerifyRequest) -> dict[str, object]:
        data = read_challenge(mkey, body.challenge)
        if data is None:
            raise HTTPException(status_code=401, detail="invalid or expired challenge")
        with session_factory() as session:
            tenant = repository.get_tenant(session, data["tenant_id"])
            principal = repository.get_principal(session, data["tenant_id"], data["principal_id"])
            if tenant is None or principal is None or principal.status != "active":
                raise HTTPException(status_code=401, detail="principal not active")
            cred = repository.get_mfa(session, principal.id)
            if cred is None or cred.confirmed_at is None:
                raise HTTPException(status_code=401, detail="mfa not enrolled")
            if not verify_code(decrypt_secret(mkey, cred.secret_encrypted), body.code):
                raise HTTPException(status_code=401, detail="invalid code")
            roles = repository.get_roles(session, principal.id)
            return _issue_login_response(session, key, principal, tenant, roles)

    @app.post("/v1/mfa/enroll")
    def mfa_enroll(body: MfaEnrollRequest) -> dict[str, str]:
        with session_factory() as session:
            principal, tenant = _authenticate(session, body.tenant, body.email, body.password)
            secret = generate_secret()
            repository.upsert_mfa_secret(session, principal.id, encrypt_secret(mkey, secret))
            uri = provisioning_uri(secret, f"{principal.email} ({tenant.slug})")
        return {"secret": secret, "provisioning_uri": uri}

    @app.post("/v1/mfa/confirm")
    def mfa_confirm(body: MfaConfirmRequest) -> dict[str, str]:
        with session_factory() as session:
            principal, _tenant = _authenticate(session, body.tenant, body.email, body.password)
            cred = repository.get_mfa(session, principal.id)
            if cred is None:
                raise HTTPException(status_code=400, detail="no pending enrollment")
            if not verify_code(decrypt_secret(mkey, cred.secret_encrypted), body.code):
                raise HTTPException(status_code=401, detail="invalid code")
            repository.confirm_mfa(session, principal.id)
        return {"status": "confirmed"}

    @app.get("/v1/me")
    def me(authorization: str = Header(default="")) -> dict[str, object]:
        grant = _grant_from_header(authorization, key)
        with session_factory() as session:
            principal = repository.get_principal(session, grant.tenant_id, grant.principal_id)
            if principal is None or principal.status != "active":
                raise HTTPException(status_code=401, detail="principal not active")
        return {
            "principal_id": grant.principal_id,
            "tenant_id": grant.tenant_id,
            "roles": grant.roles,
            "tier": grant.tier,
            "capabilities": grant.capabilities,
        }

    return app
