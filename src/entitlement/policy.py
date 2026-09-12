"""RBAC and subscription policy: capability classes, the role-by-tier matrix,
and the fail-closed entitlement verifier.

``capabilities_for`` is the authority-side computation of a principal's granted
classes; ``require_entitlement`` is the verifier used at every enforcement point.
See docs/entitlement-rbac-subscription.md sections 8, 9, and 11.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from enum import Enum

from .grant import CapabilityGrant


class CapabilityClass(Enum):
    CONTROL_PLANE_READ = "control_plane_read"
    CONTROL_PLANE_SCAN = "control_plane_scan"
    CONTROL_PLANE_ENGAGE = "control_plane_engage"
    REDTEAM_RECON = "redteam_recon"
    REDTEAM_PROBE = "redteam_probe"
    REDTEAM_EXPLOIT = "redteam_exploit"
    REDTEAM_POST_EXPLOIT = "redteam_post_exploit"
    ADMIN = "admin"


class Role(Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    ADMIN = "admin"


class Tier(Enum):
    COMMUNITY = "community"
    PRO = "pro"
    ENTERPRISE = "enterprise"


_TIER_RANK = {Tier.COMMUNITY: 0, Tier.PRO: 1, Tier.ENTERPRISE: 2}

# capability class -> (minimum tier, roles allowed). This is the single source of
# the entitlement matrix in the design note (section 9). A class is granted when
# the tenant tier meets the minimum AND the principal holds an allowed role.
_MATRIX: dict[CapabilityClass, tuple[Tier, frozenset[Role]]] = {
    CapabilityClass.CONTROL_PLANE_READ: (
        Tier.COMMUNITY,
        frozenset({Role.VIEWER, Role.ANALYST, Role.OPERATOR, Role.ADMIN}),
    ),
    CapabilityClass.CONTROL_PLANE_SCAN: (
        Tier.COMMUNITY,
        frozenset({Role.ANALYST, Role.OPERATOR}),
    ),
    # Authoring an engagement (signing the authorization manifest) is Operator-only,
    # separate from running scans under one: an Analyst may scan within an
    # Operator-authored engagement but cannot self-approve one (separation of duties).
    CapabilityClass.CONTROL_PLANE_ENGAGE: (Tier.COMMUNITY, frozenset({Role.OPERATOR})),
    CapabilityClass.REDTEAM_RECON: (Tier.PRO, frozenset({Role.ANALYST, Role.OPERATOR})),
    CapabilityClass.REDTEAM_PROBE: (Tier.PRO, frozenset({Role.ANALYST, Role.OPERATOR})),
    CapabilityClass.REDTEAM_EXPLOIT: (Tier.ENTERPRISE, frozenset({Role.OPERATOR})),
    CapabilityClass.REDTEAM_POST_EXPLOIT: (Tier.ENTERPRISE, frozenset({Role.OPERATOR})),
    CapabilityClass.ADMIN: (Tier.COMMUNITY, frozenset({Role.ADMIN})),
}


class EntitlementError(PermissionError):
    """Raised when a grant does not entitle the requested capability class."""


def _as_role(value: Role | str) -> Role:
    return value if isinstance(value, Role) else Role(value)


def _as_tier(value: Tier | str) -> Tier:
    return value if isinstance(value, Tier) else Tier(value)


def capabilities_for(roles: Iterable[Role | str], tier: Tier | str) -> list[str]:
    """Compute the capability classes a principal holds (authority side).

    Returns the class values, sorted, ready to store in a grant. This is where
    subscription (tier) and RBAC (roles) combine; the verifier never recomputes
    policy, it only checks membership of the stored set.
    """
    held = {_as_role(r) for r in roles}
    t = _as_tier(tier)
    granted = [
        cls.value
        for cls, (min_tier, allowed) in _MATRIX.items()
        if _TIER_RANK[t] >= _TIER_RANK[min_tier] and (held & allowed)
    ]
    return sorted(granted)


def require_entitlement(
    grant: CapabilityGrant | None,
    capability_class: CapabilityClass | str,
    key: bytes,
    at: datetime | None = None,
) -> None:
    """Raise EntitlementError unless a valid grant includes the capability class.

    Fail closed: a missing grant, an invalid signature, an expired grant, or a
    class the grant does not include is a deny. This checks entitlement only; the
    engagement gate (scope, engagement, token) and tenant isolation are enforced
    separately and independently.
    """
    if grant is None:
        raise EntitlementError("no grant: entitlement is required (fail closed)")
    if not grant.verify(key):
        raise EntitlementError("grant signature invalid")
    if grant.is_expired(at):
        raise EntitlementError("grant expired")
    wanted = (
        capability_class.value
        if isinstance(capability_class, CapabilityClass)
        else str(capability_class)
    )
    if not grant.allows(wanted):
        raise EntitlementError(f"grant does not include capability class: {wanted}")
