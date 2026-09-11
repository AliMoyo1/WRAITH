"""Approval-token verification and durable single-use consumption for the Runner.

A consequential (offensive) scan must carry a single-use approval token. This mirrors
the kernel's require_authorization token branch (orchestrator.ApprovalToken) but
consumes the nonce durably per tenant via repository.consume_token, so a replay is
refused across restarts and workers.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from orchestrator import ApprovalToken

from . import repository


class TokenError(Exception):
    """Raised when an approval token is missing, invalid, mismatched, or spent."""


def consume_approval_token(
    session: Session,
    tenant_id: str,
    token_dict: dict,
    key: bytes,
    engagement_id: str,
    action: str,
    target: str,
    at: datetime | None = None,
) -> None:
    """Verify a single-use approval token and consume it, or raise TokenError.

    Checks the signature, the engagement/action/target binding, and expiry before
    consuming the nonce, so an invalid token never spends a nonce. Consumption is
    atomic and durable (per tenant), so a replay is refused.
    """
    token = ApprovalToken.from_dict(token_dict)
    if not token.verify(key):
        raise TokenError("approval token signature invalid")
    if token.engagement_id != engagement_id:
        raise TokenError("approval token not bound to this engagement")
    if token.action != action:
        raise TokenError("approval token action mismatch")
    if token.target != target:
        raise TokenError("approval token target mismatch")
    if token.is_expired(at):
        raise TokenError("approval token expired")
    if not repository.consume_token(session, tenant_id, token.nonce):
        raise TokenError("approval token already used")
