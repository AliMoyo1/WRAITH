"""WRAITH entitlement: WRAITH-native RBAC and subscription.

Server-agnostic core of the entitlement axis: the signed ``CapabilityGrant``, the
role-by-tier policy matrix, and the fail-closed verifier. This axis is orthogonal
to the engagement gate in the ``orchestrator`` package: a grant answers "may this
principal use this capability class at all", never "against this target". Both
gates must pass. See docs/entitlement-rbac-subscription.md.
"""

from __future__ import annotations

from .grant import CapabilityGrant, generate_keypair, now_utc, public_from_private
from .policy import (
    CapabilityClass,
    EntitlementError,
    Role,
    Tier,
    capabilities_for,
    require_entitlement,
)

__all__ = [
    "CapabilityClass",
    "CapabilityGrant",
    "EntitlementError",
    "Role",
    "Tier",
    "capabilities_for",
    "generate_keypair",
    "now_utc",
    "public_from_private",
    "require_entitlement",
]
