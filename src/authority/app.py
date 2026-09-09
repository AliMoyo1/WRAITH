"""FastAPI application for the WRAITH authority service.

Sub-phase 2 adds email and password login (Argon2) that issues a short-lived
CapabilityGrant plus a refresh token, and GET /v1/me which reads the grant from
the Authorization header. MFA (required for Operator and Admin) lands in
sub-phase 3, and the refresh endpoint in sub-phase 4.
"""

from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session, sessionmaker

from entitlement import CapabilityGrant

from . import repository
from .config import database_url
from .config import entitlement_key as _default_entitlement_key
from .db import create_all, make_engine, make_session_factory
from .grants import decode_grant, encode_grant, issue_grant, new_refresh_token
from .security import verify_password


class LoginRequest(BaseModel):
    tenant: str
    email: str
    password: str


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
) -> FastAPI:
    if session_factory is None:
        engine = make_engine(database_url())
        create_all(engine)
        session_factory = make_session_factory(engine)
    key = entitlement_key if entitlement_key is not None else _default_entitlement_key()

    app = FastAPI(title="WRAITH Authority", version="0.2.0")
    app.state.session_factory = session_factory

    @app.get("/v1/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/auth/login")
    def login(body: LoginRequest) -> dict[str, str]:
        with session_factory() as session:
            tenant = repository.get_tenant_by_slug(session, body.tenant)
            principal = (
                repository.get_principal_by_email(session, tenant.id, body.email)
                if tenant is not None
                else None
            )
            if (
                tenant is None
                or principal is None
                or principal.status != "active"
                or not verify_password(body.password, principal.password_hash)
            ):
                # One message for every failure mode: no account enumeration.
                raise HTTPException(status_code=401, detail="invalid credentials")
            roles = repository.get_roles(session, principal.id)
            grant = issue_grant(key, tenant.id, principal.id, roles, tenant.tier)
            raw_refresh, refresh_hash = new_refresh_token()
            repository.store_refresh_token(session, principal.id, refresh_hash)
        return {
            "grant": encode_grant(grant),
            "refresh_token": raw_refresh,
            "expires_at": grant.expires_at,
        }

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
