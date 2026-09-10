"""FastAPI application for the WRAITH authority service.

Sub-phase 3 adds TOTP MFA. Enrollment and confirmation are password-authenticated
bootstrap steps. At login, a principal holding the Operator or Admin role must
have confirmed MFA: if MFA is confirmed, login returns a short-lived challenge
instead of a grant, and POST /v1/auth/mfa/verify exchanges a valid code for the
grant. A non-elevated principal without MFA still receives a grant directly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session, sessionmaker

from entitlement import CapabilityGrant, public_from_private

from . import repository
from .config import (
    database_url,
)
from .config import (
    entitlement_private_key as _default_entitlement_private_key,
)
from .config import (
    mfa_key as _default_mfa_key,
)
from .db import create_all, make_engine, make_session_factory
from .grants import (
    decode_grant,
    encode_grant,
    hash_api_key,
    hash_refresh,
    issue_grant,
    new_api_key,
    new_refresh_token,
)
from .mfa import (
    CHALLENGE_TTL_SECONDS,
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
# API-key grants are capped below the elevated classes: automation cannot trigger
# exploitation or tenant administration without an interactive, MFA-backed login.
_API_KEY_EXCLUDED = frozenset({"redteam_exploit", "redteam_post_exploit", "admin"})
# Capability marker carried only by interactive-login grants (never by a grant
# minted from an API key), so an API-key-derived grant cannot mint or revoke keys.
_API_KEY_MANAGE = "api_key_manage"
_INTERACTIVE_EXTRA = frozenset({_API_KEY_MANAGE})
_VALID_ROLES = frozenset({"viewer", "analyst", "operator", "admin"})
_VALID_TIERS = frozenset({"community", "pro", "enterprise"})
_VALID_STATUS = frozenset({"active", "disabled"})


class LoginRequest(BaseModel):
    tenant: str
    email: str
    password: str


class MfaEnrollRequest(BaseModel):
    tenant: str
    email: str
    password: str
    # Required only to re-enroll over an already-confirmed factor: a current TOTP
    # code from the existing authenticator. First-time enrollment leaves it unset.
    code: str | None = None


class MfaConfirmRequest(BaseModel):
    tenant: str
    email: str
    password: str
    code: str


class MfaVerifyRequest(BaseModel):
    challenge: str
    code: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class ApiKeyCreateRequest(BaseModel):
    name: str


class TokenRequest(BaseModel):
    api_key: str


class AdminPrincipalCreate(BaseModel):
    email: str
    password: str
    roles: list[str] = []


class AdminPrincipalUpdate(BaseModel):
    roles: list[str] | None = None
    status: str | None = None


class AdminTenantUpdate(BaseModel):
    tier: str


def _mfa_required(roles: list[str]) -> bool:
    return any(role in _MFA_ROLES for role in roles)


def _require_class(grant: CapabilityGrant, capability_class: str) -> None:
    if not grant.allows(capability_class):
        raise HTTPException(status_code=403, detail="insufficient capability")


def _validate_roles(roles: list[str]) -> None:
    unknown = [r for r in roles if r not in _VALID_ROLES]
    if unknown:
        raise HTTPException(status_code=400, detail=f"unknown role: {', '.join(unknown)}")


def _is_past(iso: str) -> bool:
    try:
        moment = datetime.fromisoformat(iso)
    except ValueError:
        return True
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment <= datetime.now(UTC)


def _require_active_tenant(tenant: Tenant) -> None:
    # A tenant can be disabled for billing or offboarding; when it is, none of its
    # principals may authenticate or use an existing grant. Checked on every path.
    if tenant.status != "active":
        raise HTTPException(status_code=403, detail="tenant disabled")


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
    # Only revealed after the credentials check, so it is not a tenant oracle.
    _require_active_tenant(tenant)
    return principal, tenant


def _issue_login_response(
    session: Session, key: bytes, principal: Principal, tenant: Tenant, roles: list[str]
) -> dict[str, object]:
    # Interactive logins carry the api_key_manage marker; grants minted from an API
    # key (issued via /v1/auth/token) do not, so a key cannot mint or revoke keys.
    grant = issue_grant(key, tenant.id, principal.id, roles, tenant.tier, extra=_INTERACTIVE_EXTRA)
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
    entitlement_private_key: bytes | None = None,
    mfa_key: bytes | None = None,
) -> FastAPI:
    if session_factory is None:
        engine = make_engine(database_url())
        create_all(engine)
        session_factory = make_session_factory(engine)
    # The authority holds only the Ed25519 private key; it signs grants with it and
    # derives the public key to verify the bearer grants it is presented. A verifier
    # (for example a future Runner) holds only the public key.
    priv = (
        entitlement_private_key
        if entitlement_private_key is not None
        else _default_entitlement_private_key()
    )
    pub = public_from_private(priv)
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
            return _issue_login_response(session, priv, principal, tenant, roles)

    @app.post("/v1/auth/mfa/verify")
    def mfa_verify(body: MfaVerifyRequest) -> dict[str, object]:
        data = read_challenge(mkey, body.challenge)
        jti = data.get("jti") if data is not None else None
        if data is None or not jti:
            raise HTTPException(status_code=401, detail="invalid or expired challenge")
        with session_factory() as session:
            # Single-use: redeem the challenge before checking the code, so a captured
            # challenge cannot be replayed to mint more than one session.
            expires_at = (
                datetime.now(UTC) + timedelta(seconds=CHALLENGE_TTL_SECONDS)
            ).isoformat()
            if not repository.consume_challenge(session, jti, expires_at):
                raise HTTPException(status_code=401, detail="challenge already used")
            tenant = repository.get_tenant(session, data["tenant_id"])
            principal = repository.get_principal(session, data["tenant_id"], data["principal_id"])
            if tenant is None or principal is None or principal.status != "active":
                raise HTTPException(status_code=401, detail="principal not active")
            _require_active_tenant(tenant)
            cred = repository.get_mfa(session, principal.id)
            if cred is None or cred.confirmed_at is None:
                raise HTTPException(status_code=401, detail="mfa not enrolled")
            if not verify_code(decrypt_secret(mkey, cred.secret_encrypted), body.code):
                raise HTTPException(status_code=401, detail="invalid code")
            roles = repository.get_roles(session, principal.id)
            return _issue_login_response(session, priv, principal, tenant, roles)

    @app.post("/v1/mfa/enroll")
    def mfa_enroll(body: MfaEnrollRequest) -> dict[str, str]:
        with session_factory() as session:
            principal, tenant = _authenticate(session, body.tenant, body.email, body.password)
            existing = repository.get_mfa(session, principal.id)
            if existing is not None and existing.confirmed_at is not None:
                # Replacing an already-confirmed factor requires proof of the current
                # factor: a valid code from the existing authenticator. Without this a
                # stolen password alone could swap in an attacker's authenticator and
                # defeat MFA entirely (account takeover). First-time enrollment, where
                # no confirmed factor exists yet, remains a password-only bootstrap.
                current = decrypt_secret(mkey, existing.secret_encrypted)
                if not body.code or not verify_code(current, body.code):
                    raise HTTPException(
                        status_code=403,
                        detail="re-enrollment requires a current mfa code",
                    )
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

    @app.post("/v1/auth/refresh")
    def refresh(body: RefreshRequest) -> dict[str, object]:
        with session_factory() as session:
            stored = repository.get_refresh_token(session, hash_refresh(body.refresh_token))
            if stored is None or stored.revoked or _is_past(stored.expires_at):
                raise HTTPException(status_code=401, detail="invalid refresh token")
            principal = repository.get_principal_by_id(session, stored.principal_id)
            tenant = (
                repository.get_tenant(session, principal.tenant_id)
                if principal is not None
                else None
            )
            if principal is None or principal.status != "active" or tenant is None:
                raise HTTPException(status_code=401, detail="principal not active")
            _require_active_tenant(tenant)
            roles = repository.get_roles(session, principal.id)
            # Rotate atomically: only the caller that flips the token from active to
            # revoked mints a new session, so a concurrent reuse of the same token
            # cannot both pass the check above and both succeed.
            if not repository.revoke_refresh_if_active(session, stored.id):
                raise HTTPException(status_code=401, detail="refresh token already rotated")
            return _issue_login_response(session, priv, principal, tenant, roles)

    @app.post("/v1/auth/logout")
    def logout(body: LogoutRequest) -> dict[str, str]:
        # Server-side revocation of the presented refresh token so logout is not
        # merely local. Idempotent and always 200: an unknown or already-revoked
        # token is not distinguished, so this is not a token oracle.
        with session_factory() as session:
            stored = repository.get_refresh_token(session, hash_refresh(body.refresh_token))
            if stored is not None and not stored.revoked:
                repository.revoke_refresh_if_active(session, stored.id)
        return {"status": "logged out"}

    @app.post("/v1/api-keys")
    def api_key_create(
        body: ApiKeyCreateRequest, authorization: str = Header(default="")
    ) -> dict[str, object]:
        grant = _grant_from_header(authorization, pub)
        _require_class(grant, _API_KEY_MANAGE)  # deny grants minted from an API key
        raw, key_hash = new_api_key()
        with session_factory() as session:
            record = repository.create_api_key(
                session, grant.tenant_id, grant.principal_id, body.name, key_hash
            )
            payload: dict[str, object] = {
                "id": record.id,
                "name": record.name,
                "api_key": raw,
                "created_at": record.created_at,
            }
        return payload

    @app.get("/v1/api-keys")
    def api_key_list(authorization: str = Header(default="")) -> dict[str, object]:
        grant = _grant_from_header(authorization, pub)
        with session_factory() as session:
            records = repository.list_api_keys(session, grant.tenant_id, grant.principal_id)
            keys = [
                {
                    "id": r.id,
                    "name": r.name,
                    "created_at": r.created_at,
                    "last_used_at": r.last_used_at,
                    "revoked_at": r.revoked_at,
                }
                for r in records
            ]
        return {"api_keys": keys}

    @app.delete("/v1/api-keys/{key_id}")
    def api_key_revoke(key_id: str, authorization: str = Header(default="")) -> dict[str, str]:
        grant = _grant_from_header(authorization, pub)
        _require_class(grant, _API_KEY_MANAGE)  # deny grants minted from an API key
        with session_factory() as session:
            record = repository.get_api_key_by_id(
                session, grant.tenant_id, grant.principal_id, key_id
            )
            if record is None:
                raise HTTPException(status_code=404, detail="api key not found")
            repository.revoke_api_key(session, record)
        return {"status": "revoked"}

    @app.post("/v1/auth/token")
    def auth_token(body: TokenRequest) -> dict[str, object]:
        with session_factory() as session:
            record = repository.get_api_key(session, hash_api_key(body.api_key))
            if record is None or record.revoked_at is not None:
                raise HTTPException(status_code=401, detail="invalid api key")
            principal = repository.get_principal_by_id(session, record.principal_id)
            tenant = repository.get_tenant(session, record.tenant_id)
            if principal is None or principal.status != "active" or tenant is None:
                raise HTTPException(status_code=401, detail="principal not active")
            _require_active_tenant(tenant)
            repository.touch_api_key(session, record)
            roles = repository.get_roles(session, principal.id)
            grant = issue_grant(
                priv, tenant.id, principal.id, roles, tenant.tier, exclude=_API_KEY_EXCLUDED
            )
            payload: dict[str, object] = {
                "grant": encode_grant(grant),
                "expires_at": grant.expires_at,
            }
            return payload

    @app.post("/v1/admin/principals")
    def admin_create_principal(
        body: AdminPrincipalCreate, authorization: str = Header(default="")
    ) -> dict[str, object]:
        grant = _grant_from_header(authorization, pub)
        _require_class(grant, "admin")
        _validate_roles(body.roles)
        with session_factory() as session:
            if repository.get_principal_by_email(session, grant.tenant_id, body.email) is not None:
                raise HTTPException(status_code=409, detail="email already exists")
            principal = repository.create_principal(
                session, grant.tenant_id, body.email, body.password, body.roles
            )
            payload: dict[str, object] = {
                "id": principal.id,
                "email": principal.email,
                "roles": sorted(body.roles),
            }
        return payload

    @app.get("/v1/admin/principals")
    def admin_list_principals(authorization: str = Header(default="")) -> dict[str, object]:
        grant = _grant_from_header(authorization, pub)
        _require_class(grant, "admin")
        with session_factory() as session:
            rows = [
                {
                    "id": p.id,
                    "email": p.email,
                    "status": p.status,
                    "roles": sorted(repository.get_roles(session, p.id)),
                }
                for p in repository.list_principals(session, grant.tenant_id)
            ]
        return {"principals": rows}

    @app.patch("/v1/admin/principals/{principal_id}")
    def admin_update_principal(
        principal_id: str, body: AdminPrincipalUpdate, authorization: str = Header(default="")
    ) -> dict[str, object]:
        grant = _grant_from_header(authorization, pub)
        _require_class(grant, "admin")
        with session_factory() as session:
            principal = repository.get_principal(session, grant.tenant_id, principal_id)
            if principal is None:
                raise HTTPException(status_code=404, detail="principal not found")
            if body.roles is not None:
                _validate_roles(body.roles)
                repository.set_roles(session, principal.id, body.roles)
            if body.status is not None:
                if body.status not in _VALID_STATUS:
                    raise HTTPException(status_code=400, detail="invalid status")
                repository.set_principal_status(session, principal, body.status)
            payload: dict[str, object] = {
                "id": principal.id,
                "email": principal.email,
                "status": principal.status,
                "roles": sorted(repository.get_roles(session, principal.id)),
            }
        return payload

    @app.patch("/v1/admin/tenant")
    def admin_update_tenant(
        body: AdminTenantUpdate, authorization: str = Header(default="")
    ) -> dict[str, object]:
        grant = _grant_from_header(authorization, pub)
        _require_class(grant, "admin")
        if body.tier not in _VALID_TIERS:
            raise HTTPException(status_code=400, detail="invalid tier")
        with session_factory() as session:
            tenant = repository.get_tenant(session, grant.tenant_id)
            if tenant is None:
                raise HTTPException(status_code=404, detail="tenant not found")
            repository.set_tenant_tier(session, tenant, body.tier)
            payload: dict[str, object] = {"id": tenant.id, "tier": tenant.tier}
        return payload

    @app.get("/v1/me")
    def me(authorization: str = Header(default="")) -> dict[str, object]:
        grant = _grant_from_header(authorization, pub)
        with session_factory() as session:
            principal = repository.get_principal(session, grant.tenant_id, grant.principal_id)
            if principal is None or principal.status != "active":
                raise HTTPException(status_code=401, detail="principal not active")
            tenant = repository.get_tenant(session, grant.tenant_id)
            if tenant is None:
                raise HTTPException(status_code=401, detail="principal not active")
            _require_active_tenant(tenant)
        return {
            "principal_id": grant.principal_id,
            "tenant_id": grant.tenant_id,
            "roles": grant.roles,
            "tier": grant.tier,
            "capabilities": grant.capabilities,
        }

    return app
