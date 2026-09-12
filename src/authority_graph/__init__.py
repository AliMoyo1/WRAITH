"""WRAITH effective-authority graph.

Composes the entitlement gate (role-by-tier matrix) and the engagement gate (scope,
engagement, single-use approval token) into one reachability picture for a principal.
See graph.py.
"""

from __future__ import annotations

from .graph import (
    Activity,
    ActivityKind,
    AuthorityGraph,
    AuthorizationContext,
    build_authority_graph,
)

__all__ = [
    "Activity",
    "ActivityKind",
    "AuthorityGraph",
    "AuthorizationContext",
    "build_authority_graph",
]
