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

from .models import ConsumedToken, Engagement, KillSwitch, Scan


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


def set_scan_status(
    session: Session, scan: Scan, status: str, finished_at: str | None = None
) -> None:
    scan.status = status
    if finished_at is not None:
        scan.finished_at = finished_at
    session.commit()


_GLOBAL_KILL = "global"


def engage_kill(session: Session, scope: str) -> None:
    """Engage the kill-switch for a scope ("global" or a tenant id). Idempotent."""
    if session.get(KillSwitch, scope) is None:
        session.add(KillSwitch(scope=scope, engaged_at=datetime.now(UTC).isoformat()))
        session.commit()


def clear_kill(session: Session, scope: str) -> None:
    """Clear the kill-switch for a scope. Idempotent."""
    row = session.get(KillSwitch, scope)
    if row is not None:
        session.delete(row)
        session.commit()


def is_killed(session: Session, tenant_id: str) -> bool:
    """True when the global kill is engaged or this tenant's kill is engaged."""
    if session.get(KillSwitch, _GLOBAL_KILL) is not None:
        return True
    return session.get(KillSwitch, tenant_id) is not None
