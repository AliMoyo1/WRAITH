"""Tenant-scoped data access for the Runner.

Every read and write is bound to a ``tenant_id`` derived from the verified grant.
Nothing here accepts a client-supplied tenant id to reach another tenant's rows:
that is the isolation invariant, exercised by tests/test_runner.py.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Scan


def create_scan(
    session: Session,
    tenant_id: str,
    target: str,
    track: str,
    engagement_id: str | None = None,
    status: str = "queued",
) -> Scan:
    scan = Scan(
        id=uuid.uuid4().hex,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        target=target,
        track=track,
        status=status,
        created_at=datetime.now(UTC).isoformat(),
    )
    session.add(scan)
    session.commit()
    return scan


def get_scan(session: Session, tenant_id: str, scan_id: str) -> Scan | None:
    stmt = select(Scan).where(Scan.id == scan_id, Scan.tenant_id == tenant_id)
    return session.scalars(stmt).first()


def list_scans(session: Session, tenant_id: str) -> list[Scan]:
    stmt = select(Scan).where(Scan.tenant_id == tenant_id)
    return list(session.scalars(stmt))
