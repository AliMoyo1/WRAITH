"""Authority storage models. Multi-tenant: every row except Tenant is
tenant-scoped, and the tenant is never taken from the client for cross-tenant
reads (see repository.py).

Sub-phase 2 adds password hashes, roles, and refresh tokens for login. MFA and
API keys land in later sub-phases.
"""

from __future__ import annotations

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class Tenant(Base):
    __tablename__ = "tenant"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    tier: Mapped[str] = mapped_column(String(32), default="community")
    status: Mapped[str] = mapped_column(String(32), default="active")


class Principal(Base):
    __tablename__ = "principal"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_principal_tenant_email"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenant.id"), index=True)
    email: Mapped[str] = mapped_column(String(320))
    password_hash: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="active")


class PrincipalRole(Base):
    __tablename__ = "principal_role"

    principal_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("principal.id"), primary_key=True
    )
    role: Mapped[str] = mapped_column(String(32), primary_key=True)


class RefreshToken(Base):
    __tablename__ = "refresh_token"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    principal_id: Mapped[str] = mapped_column(String(64), ForeignKey("principal.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    issued_at: Mapped[str] = mapped_column(String(40))
    expires_at: Mapped[str] = mapped_column(String(40))
    revoked: Mapped[bool] = mapped_column(default=False)


class MfaCredential(Base):
    __tablename__ = "mfa_credential"

    principal_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("principal.id"), primary_key=True
    )
    type: Mapped[str] = mapped_column(String(16), default="totp")
    secret_encrypted: Mapped[str] = mapped_column(String(255))
    confirmed_at: Mapped[str | None] = mapped_column(String(40), nullable=True, default=None)


class ApiKey(Base):
    __tablename__ = "api_key"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenant.id"), index=True)
    principal_id: Mapped[str] = mapped_column(String(64), ForeignKey("principal.id"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    key_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    created_at: Mapped[str] = mapped_column(String(40))
    last_used_at: Mapped[str | None] = mapped_column(String(40), nullable=True, default=None)
    revoked_at: Mapped[str | None] = mapped_column(String(40), nullable=True, default=None)


class ConsumedChallenge(Base):
    """One-time MFA login challenges that have already been redeemed.

    A challenge's jti is inserted here when it is presented at /v1/auth/mfa/verify;
    the unique primary key makes a second presentation of the same challenge fail,
    so a captured challenge cannot mint more than one session. Rows past their
    expiry are pruned opportunistically (see repository.consume_challenge).
    """

    __tablename__ = "consumed_challenge"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[str] = mapped_column(String(40))
