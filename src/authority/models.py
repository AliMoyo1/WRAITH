"""Authority storage models. Multi-tenant: every row except Tenant is
tenant-scoped, and the tenant is never taken from the client for cross-tenant
reads (see repository.py).

Sub-phase 1 defines only what the skeleton and the isolation test need. Password
hashes, roles, MFA, API keys, and refresh tokens land in later sub-phases.
"""

from __future__ import annotations

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class Tenant(Base):
    __tablename__ = "tenant"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
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
    status: Mapped[str] = mapped_column(String(32), default="active")
