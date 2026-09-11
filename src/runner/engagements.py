"""Engagement helpers for the Runner.

The Runner stores engagements tenant-scoped (runner.models.Engagement) but enforces
them with the kernel's own orchestrator.Engagement, so the authorization semantics
(signature, expiry, open, scope) are exactly the kernel's. These helpers build a
Scope from a submitted spec, mint and sign an engagement, and rehydrate a stored row
back into a kernel Engagement for enforcement.
"""

from __future__ import annotations

import json
from datetime import timedelta

from orchestrator import Engagement, Scope, ScopeList, now_utc

from .models import Engagement as EngagementRow


def scope_from_spec(spec: dict) -> Scope:
    """Build a kernel Scope from a submitted allowlist/blocklist spec."""

    def _list(node: dict) -> ScopeList:
        return ScopeList(
            cidrs=list(node.get("cidrs", []) or []),
            domains=list(node.get("domains", []) or []),
            urls=list(node.get("urls", []) or []),
            repo_paths=list(node.get("repo_paths", []) or []),
        )

    return Scope(
        allow=_list(spec.get("allowlist") or {}),
        block=_list(spec.get("blocklist") or {}),
        enabled=bool(spec.get("enabled", True)),
        allow_metadata=bool(spec.get("allow_metadata", False)),
        block_private=bool(spec.get("block_private", False)),
    )


def build_engagement(
    engagement_id: str, created_by: str, scope: Scope, ttl_minutes: int, key: bytes
) -> Engagement:
    """Build and HMAC-sign a kernel Engagement for storage."""
    now = now_utc()
    engagement = Engagement(
        id=engagement_id,
        authorized_by=created_by,
        approved_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=ttl_minutes)).isoformat(),
        scope=scope,
        open=True,
    )
    return engagement.sign(key)


def engagement_from_row(row: EngagementRow) -> Engagement:
    """Rehydrate a stored engagement into a kernel Engagement for enforcement.

    The scope is rebuilt from the stored spec so its fingerprint (and therefore the
    signature) matches exactly.
    """
    return Engagement(
        id=row.id,
        authorized_by=row.created_by,
        approved_at=row.approved_at,
        expires_at=row.expires_at,
        scope=scope_from_spec(json.loads(row.scope_json)),
        open=row.open,
        signature=row.signature,
    )
