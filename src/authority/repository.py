"""Tenant-scoped data access.

Every read and write is bound to a ``tenant_id`` derived from the authenticated
caller. Nothing here accepts a client-supplied tenant id to reach another
tenant's rows; that is the multi-tenant isolation invariant, exercised by
tests/test_authority.py.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import cast

from sqlalchemy import delete, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import (
    ApiKey,
    ConsumedChallenge,
    MfaCredential,
    Principal,
    PrincipalRole,
    RefreshToken,
    Tenant,
)
from .security import hash_password


def create_tenant(session: Session, name: str, slug: str, tier: str = "community") -> Tenant:
    tenant = Tenant(id=uuid.uuid4().hex, name=name, slug=slug, tier=tier)
    session.add(tenant)
    session.commit()
    return tenant


def get_tenant_by_slug(session: Session, slug: str) -> Tenant | None:
    return session.scalars(select(Tenant).where(Tenant.slug == slug)).first()


def create_principal(
    session: Session,
    tenant_id: str,
    email: str,
    password: str,
    roles: list[str] | None = None,
) -> Principal:
    principal = Principal(
        id=uuid.uuid4().hex,
        tenant_id=tenant_id,
        email=email,
        password_hash=hash_password(password),
    )
    session.add(principal)
    for role in roles or []:
        session.add(PrincipalRole(principal_id=principal.id, role=role))
    session.commit()
    return principal


def get_principal_by_email(session: Session, tenant_id: str, email: str) -> Principal | None:
    stmt = select(Principal).where(Principal.tenant_id == tenant_id, Principal.email == email)
    return session.scalars(stmt).first()


def get_principal(session: Session, tenant_id: str, principal_id: str) -> Principal | None:
    stmt = select(Principal).where(Principal.tenant_id == tenant_id, Principal.id == principal_id)
    return session.scalars(stmt).first()


def get_roles(session: Session, principal_id: str) -> list[str]:
    stmt = select(PrincipalRole.role).where(PrincipalRole.principal_id == principal_id)
    return list(session.scalars(stmt))


def list_principals(session: Session, tenant_id: str) -> list[Principal]:
    stmt = select(Principal).where(Principal.tenant_id == tenant_id)
    return list(session.scalars(stmt))


def store_refresh_token(
    session: Session, principal_id: str, token_hash: str, ttl_hours: int = 8
) -> RefreshToken:
    now = datetime.now(UTC)
    token = RefreshToken(
        id=uuid.uuid4().hex,
        principal_id=principal_id,
        token_hash=token_hash,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(hours=ttl_hours)).isoformat(),
    )
    session.add(token)
    session.commit()
    return token


def get_tenant(session: Session, tenant_id: str) -> Tenant | None:
    return session.get(Tenant, tenant_id)


def get_mfa(session: Session, principal_id: str) -> MfaCredential | None:
    return session.get(MfaCredential, principal_id)


def upsert_mfa_secret(
    session: Session, principal_id: str, secret_encrypted: str
) -> MfaCredential:
    cred = session.get(MfaCredential, principal_id)
    if cred is None:
        cred = MfaCredential(principal_id=principal_id, secret_encrypted=secret_encrypted)
        session.add(cred)
    else:
        # Re-enrolling replaces the secret and clears the prior confirmation.
        cred.secret_encrypted = secret_encrypted
        cred.confirmed_at = None
    session.commit()
    return cred


def confirm_mfa(session: Session, principal_id: str) -> None:
    cred = session.get(MfaCredential, principal_id)
    if cred is not None:
        cred.confirmed_at = datetime.now(UTC).isoformat()
        session.commit()


def get_principal_by_id(session: Session, principal_id: str) -> Principal | None:
    return session.get(Principal, principal_id)


def get_refresh_token(session: Session, token_hash: str) -> RefreshToken | None:
    stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    return session.scalars(stmt).first()


def revoke_refresh_token(session: Session, token: RefreshToken) -> None:
    token.revoked = True
    session.commit()


def revoke_refresh_if_active(session: Session, token_id: str) -> bool:
    """Atomically revoke a refresh token, returning True only for the caller that

    won the race. Rotation reads, checks, and revokes in separate steps, so a
    concurrent reuse of the same token could otherwise both pass the check; the
    conditional UPDATE (only where it is still active) lets exactly one caller
    flip it and mint a new session.
    """
    result = session.execute(
        update(RefreshToken)
        .where(RefreshToken.id == token_id, ~RefreshToken.revoked)
        .values(revoked=True)
    )
    session.commit()
    return cast(CursorResult, result).rowcount == 1


def consume_challenge(session: Session, jti: str, expires_at: str) -> bool:
    """Record a one-time MFA challenge, returning False if it was already used.

    Expired rows are pruned first so the table stays bounded. The unique primary
    key on jti makes a replayed challenge fail to insert, which is reported as a
    replay (False) rather than raising.
    """
    now = datetime.now(UTC).isoformat()
    session.execute(delete(ConsumedChallenge).where(ConsumedChallenge.expires_at < now))
    session.add(ConsumedChallenge(jti=jti, expires_at=expires_at))
    try:
        session.commit()
        return True
    except IntegrityError:
        session.rollback()
        return False


def create_api_key(
    session: Session, tenant_id: str, principal_id: str, name: str, key_hash: str
) -> ApiKey:
    record = ApiKey(
        id=uuid.uuid4().hex,
        tenant_id=tenant_id,
        principal_id=principal_id,
        name=name,
        key_hash=key_hash,
        created_at=datetime.now(UTC).isoformat(),
    )
    session.add(record)
    session.commit()
    return record


def get_api_key(session: Session, key_hash: str) -> ApiKey | None:
    return session.scalars(select(ApiKey).where(ApiKey.key_hash == key_hash)).first()


def list_api_keys(session: Session, tenant_id: str, principal_id: str) -> list[ApiKey]:
    stmt = select(ApiKey).where(
        ApiKey.tenant_id == tenant_id, ApiKey.principal_id == principal_id
    )
    return list(session.scalars(stmt))


def get_api_key_by_id(
    session: Session, tenant_id: str, principal_id: str, key_id: str
) -> ApiKey | None:
    stmt = select(ApiKey).where(
        ApiKey.id == key_id,
        ApiKey.tenant_id == tenant_id,
        ApiKey.principal_id == principal_id,
    )
    return session.scalars(stmt).first()


def revoke_api_key(session: Session, record: ApiKey) -> None:
    record.revoked_at = datetime.now(UTC).isoformat()
    session.commit()


def touch_api_key(session: Session, record: ApiKey) -> None:
    record.last_used_at = datetime.now(UTC).isoformat()
    session.commit()


def set_roles(session: Session, principal_id: str, roles: list[str]) -> None:
    session.execute(delete(PrincipalRole).where(PrincipalRole.principal_id == principal_id))
    for role in roles:
        session.add(PrincipalRole(principal_id=principal_id, role=role))
    session.commit()


def set_principal_status(session: Session, principal: Principal, status: str) -> None:
    principal.status = status
    session.commit()


def set_tenant_tier(session: Session, tenant: Tenant, tier: str) -> None:
    tenant.tier = tier
    session.commit()
