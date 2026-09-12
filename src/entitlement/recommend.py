"""Least-privilege recommendations over the entitlement matrix.

Given the capability classes a principal actually needs, compute the minimal role set
and tier that grant them, and compare that against what a grant currently holds to
flag over-provisioning. Pure policy analysis (no usage tracking): it reasons over the
role-by-tier matrix in policy.py.
"""

from __future__ import annotations

from collections.abc import Iterable
from itertools import combinations

from .policy import Role, Tier, capabilities_for


def minimal_roles_tier(needed: Iterable[str]) -> tuple[frozenset[Role], Tier] | None:
    """Return the least-privilege (roles, tier) whose capabilities cover ``needed``.

    Lowest tier first (Tier is declared ascending), then the fewest roles. Returns
    None if no role set at any tier grants every needed class (for example a class the
    matrix never confers, like the issuance-only ``api_key_manage`` marker).
    """
    want = set(needed)
    for tier in Tier:  # enum order is ascending: Community, Pro, Enterprise
        for size in range(1, len(Role) + 1):
            for combo in combinations(Role, size):
                if want <= set(capabilities_for(combo, tier)):
                    return frozenset(combo), tier
    return None


def analyze_grant(roles: Iterable[str], tier: str, needed: Iterable[str]) -> dict:
    """Compare a current (roles, tier) grant against the classes actually needed.

    Reports what is held but unused (over-provisioning), what is needed but missing
    (under-provisioning), and the least-privilege assignment that covers ``needed``.
    Raises ValueError (from capabilities_for) on an unknown role or tier.
    """
    current = set(capabilities_for(roles, tier))
    want = set(needed)
    rec = minimal_roles_tier(want)
    return {
        "current_capabilities": sorted(current),
        "needed": sorted(want),
        "unused": sorted(current - want),
        "missing": sorted(want - current),
        "over_provisioned": bool(current - want),
        "recommended_roles": sorted(r.value for r in rec[0]) if rec else None,
        "recommended_tier": rec[1].value if rec else None,
    }
