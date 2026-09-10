"""Runner storage models.

Every row is tenant-scoped, and the tenant is taken from the verified grant, never
from client input (see repository.py). This is the tenant-isolation invariant,
exercised by tests/test_runner.py. Engagement records, scans as executed jobs, and
per-tenant encrypted results are filled in over later sub-phases.
"""

from __future__ import annotations

from sqlalchemy import String
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
