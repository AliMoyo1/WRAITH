"""WRAITH orchestrator package.

Public API for scope enforcement, engagement authorization, and dependency-aware
routing. The real logic lives in the submodules:

  * scope.py       - deterministic target matching (CIDR / domain / URL / path)
  * engagement.py  - signed, expiring engagement records and approval tokens
  * policy.py      - the Orchestrator enforcement point and routing

See WRAITH.md Section 11.1 (Authorization / Rules of Engagement).
"""

from __future__ import annotations

from .engagement import ApprovalToken, Engagement, now_utc
from .policy import Orchestrator, RouteResult, Track
from .scope import Scope, ScopeList

__all__ = [
    "ApprovalToken",
    "Engagement",
    "Orchestrator",
    "RouteResult",
    "Scope",
    "ScopeList",
    "Track",
    "now_utc",
]
