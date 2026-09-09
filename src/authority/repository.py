"""Tenant-scoped data access.

Every read and write is bound to a ``tenant_id`` derived from the authenticated
caller. Nothing here accepts a client-supplied tenant id to reach another
tenant's rows; that is the multi-tenant isolation invariant, exercised by
tests/test_authority.py.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Principal, Tenant


def create_tenant(session: Session, name: str, tier: str = "community") -> Tenant:
    tenant = Tenant(id=uuid.uuid4().hex, name=name, tier=tier)
    session.add(tenant)
    session.commit()
    return tenant


def create_principal(session: Session, tenant_id: str, email: str) -> Principal:
    principal = Principal(id=uuid.uuid4().hex, tenant_id=tenant_id, email=email)
    session.add(principal)
    session.commit()
    return principal


def list_principals(session: Session, tenant_id: str) -> list[Principal]:
    stmt = select(Principal).where(Principal.tenant_id == tenant_id)
    return list(session.scalars(stmt))
