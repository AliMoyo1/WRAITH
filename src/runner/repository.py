"""Tenant-scoped data access for the Runner.

Every read and write is bound to a ``tenant_id`` derived from the verified grant.
Nothing here accepts a client-supplied tenant id to reach another tenant's rows:
that is the isolation invariant, exercised by tests/test_runner.py.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import ConsumedToken, Engagement, Scan


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


def create_engagement(
    session: Session,
    engagement_id: str,
    tenant_id: str,
    created_by: str,
    scope_json: str,
    approved_at: str,
    expires_at: str,
    signature: str,
) -> Engagement:
    record = Engagement(
        id=engagement_id,
        tenant_id=tenant_id,
        created_by=created_by,
        scope_json=scope_json,
        approved_at=approved_at,
        expires_at=expires_at,
        signature=signature,
    )
    session.add(record)
    session.commit()
    return record


def get_engagement(session: Session, tenant_id: str, engagement_id: str) -> Engagement | None:
    stmt = select(Engagement).where(
        Engagement.id == engagement_id, Engagement.tenant_id == tenant_id
    )
    return session.scalars(stmt).first()


def close_engagement(session: Session, record: Engagement) -> None:
    record.open = False
    session.commit()


def consume_token(session: Session, tenant_id: str, nonce: str) -> bool:
    """Record a single-use token nonce for a tenant, returning False on replay.

    The (tenant_id, nonce) primary key makes the insert fail if the nonce was already
    spent for this tenant; that is reported as a replay (False), not raised.
    """
    session.add(
        ConsumedToken(tenant_id=tenant_id, nonce=nonce, consumed_at=datetime.now(UTC).isoformat())
    )
    try:
        session.commit()
        return True
    except IntegrityError:
        session.rollback()
        return False
