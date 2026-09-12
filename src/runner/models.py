"""Runner storage models.

Every row is tenant-scoped, and the tenant is taken from the verified grant, never
from client input (see repository.py). This is the tenant-isolation invariant,
exercised by tests/test_runner.py. Engagement records, scans as executed jobs, and
per-tenant encrypted results are filled in over later sub-phases.
"""

from __future__ import annotations

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class Scan(Base):
    """A scan request, tenant-scoped.

    In the skeleton this is a stored record only; enqueueing, the worker running
    the supervisor, and per-tenant results arrive in sub-phase 4. ``engagement_id``
    is a plain string for now (engagement records land in sub-phase 3).
    """

    __tablename__ = "scan"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    engagement_id: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None)
    target: Mapped[str] = mapped_column(String(2048))
    track: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), default="queued")
    created_at: Mapped[str] = mapped_column(String(40))
    finished_at: Mapped[str | None] = mapped_column(String(40), nullable=True, default=None)
    # Per-engine coverage summary as JSON: [{name, version, status, coverage}, ...].
    # Set when the worker finishes so the scan API can report which engines ran, were
    # unavailable, or errored, rather than collapsing everything into a single status.
    engines_json: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)


class Engagement(Base):
    """A tenant-scoped, HMAC-signed authorization record for a set of scans.

    Mirrors orchestrator.Engagement, which the Runner rehydrates to enforce it:
    scope, approval and expiry, an open flag, and the signature over the immutable
    fields. The scope is stored as the submitted JSON spec so it can be rebuilt
    exactly (the signature covers the scope fingerprint). ``open`` is a
    server-controlled column, so a client cannot flip a closed engagement open.
    """

    __tablename__ = "engagement"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    created_by: Mapped[str] = mapped_column(String(255))
    scope_json: Mapped[str] = mapped_column(Text)
    approved_at: Mapped[str] = mapped_column(String(40))
    expires_at: Mapped[str] = mapped_column(String(40))
    open: Mapped[bool] = mapped_column(default=True)
    signature: Mapped[str] = mapped_column(String(128))


class ConsumedToken(Base):
    """A spent single-use approval-token nonce, for durable replay refusal.

    The (tenant_id, nonce) composite primary key makes consumption tenant-scoped: a
    nonce spends once per tenant, and a second attempt fails to insert.
    """

    __tablename__ = "consumed_token"

    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    consumed_at: Mapped[str] = mapped_column(String(40))


class KillSwitch(Base):
    """Control-plane kill state. A row means killed for its scope: the literal
    "global" (all tenants) or a tenant id (that tenant only). Engage inserts, reset
    deletes. Durable, so it survives restarts and every worker sees it.
    """

    __tablename__ = "kill_switch"

    scope: Mapped[str] = mapped_column(String(64), primary_key=True)
    engaged_at: Mapped[str] = mapped_column(String(40))
