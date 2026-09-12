"""Effective-authority graph: compose the entitlement gate and the engagement gate
into one reachability picture for a principal.

WRAITH authorizes on two independent axes. The entitlement gate (``entitlement.policy``)
answers "may this principal use this capability class at all", derived from the
role-by-tier matrix. The engagement gate (``orchestrator.policy`` and
``orchestrator.engagement``) answers "against this target, now": scope plus an open,
signed, unexpired engagement gate every engine invocation, and consequential actions
(exploitation, post-exploitation) additionally require a single-use, target-bound
approval token. Holding a capability class is necessary but never sufficient: a grant
authorizes a class, never a target.

This module makes that composition explicit. For a principal (roles, tier) it builds a
graph: principal -> capability classes (with the entitlement reason each is granted or
blocked) -> the kernel activity each held class drives (with the engagement conditions
that still gate it) -> the kernel tracks reachable. The result is the principal's
effective authority: not just what classes they hold, but what they can actually reach
end to end and what further context each action still requires.

Pure analysis over the two policy models. It grants nothing and invokes nothing.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from entitlement.policy import (
    CapabilityClass,
    Role,
    Tier,
    capabilities_for,
    entitlement_matrix,
    tier_meets,
)
from orchestrator.policy import Track


class ActivityKind(Enum):
    CONTROL_PLANE = "control_plane"      # platform read; not target-directed
    ANALYSIS = "analysis"                # engine analysis; scope + engagement
    CONSEQUENTIAL = "consequential"      # exploit / post-exploit; + single-use token
    ADMINISTRATIVE = "administrative"    # tenant administration; not target-directed


_TARGET_DIRECTED = frozenset({ActivityKind.ANALYSIS, ActivityKind.CONSEQUENTIAL})

# Engagement-gate conditions that still apply to an activity even once the entitlement
# gate has passed. Mirrors orchestrator.Orchestrator.require_authorization: every
# target-directed activity needs scope plus an open engagement; consequential activities
# additionally need a single-use, target-bound approval token.
_CONDITIONS: dict[ActivityKind, tuple[str, ...]] = {
    ActivityKind.CONTROL_PLANE: (),
    ActivityKind.ANALYSIS: ("scope", "open_engagement"),
    ActivityKind.CONSEQUENTIAL: ("scope", "open_engagement", "single_use_approval_token"),
    ActivityKind.ADMINISTRATIVE: (),
}


@dataclass(frozen=True)
class Activity:
    """A kernel activity a capability class authorizes a principal to drive.

    ``tracks`` are the kernel ``Track`` values reachable through the activity. The
    concrete analysis track is chosen per finding by the kernel router at run time, so
    an analysis activity reaches the whole analysis track set rather than one track.
    """

    id: str
    kind: ActivityKind
    label: str
    tracks: tuple[str, ...]

    @property
    def target_directed(self) -> bool:
        return self.kind in _TARGET_DIRECTED

    @property
    def conditions(self) -> tuple[str, ...]:
        return _CONDITIONS[self.kind]

    def as_node(self) -> dict:
        return {
            "id": self.id,
            "kind": "activity",
            "activity": self.kind.value,
            "label": self.label,
            "target_directed": self.target_directed,
            "conditions": list(self.conditions),
            "tracks": list(self.tracks),
        }


_ANALYSIS_TRACKS = (Track.WEB_API.value, Track.NETWORK_CLOUD.value, Track.SAST_AGENTIC.value)

_CONTROL_PLANE = Activity("activity:control_plane", ActivityKind.CONTROL_PLANE, "Control-plane read", ())
_ANALYSIS = Activity("activity:analysis", ActivityKind.ANALYSIS, "Engine analysis", _ANALYSIS_TRACKS)
_EXPLOITATION = Activity(
    "activity:exploitation", ActivityKind.CONSEQUENTIAL, "Exploitation", (Track.EXPLOITATION.value,)
)
_POST_EXPLOIT = Activity(
    "activity:post_exploit", ActivityKind.CONSEQUENTIAL, "Post-exploitation", (Track.POST_EXPLOIT.value,)
)
_ADMINISTRATION = Activity("activity:administration", ActivityKind.ADMINISTRATIVE, "Tenant administration", ())

# capability class -> the activity it drives. The single source of the composition
# model between the two axes (see docs/authority-graph-plan.md).
_ACTIVITY_FOR: dict[CapabilityClass, Activity] = {
    CapabilityClass.CONTROL_PLANE_READ: _CONTROL_PLANE,
    CapabilityClass.CONTROL_PLANE_SCAN: _ANALYSIS,
    CapabilityClass.REDTEAM_RECON: _ANALYSIS,
    CapabilityClass.REDTEAM_PROBE: _ANALYSIS,
    CapabilityClass.REDTEAM_EXPLOIT: _EXPLOITATION,
    CapabilityClass.REDTEAM_POST_EXPLOIT: _POST_EXPLOIT,
    CapabilityClass.ADMIN: _ADMINISTRATION,
}


@dataclass
class AuthorityGraph:
    """A principal's effective authority as a graph of nodes and gated edges."""

    roles: list[str]
    tier: str
    nodes: list[dict]
    edges: list[dict]
    reachability: dict

    def to_dict(self) -> dict:
        return {
            "principal": {"roles": self.roles, "tier": self.tier},
            "nodes": self.nodes,
            "edges": self.edges,
            "reachability": self.reachability,
        }


def _norm_roles(roles: Iterable[Role | str]) -> frozenset[Role]:
    return frozenset(r if isinstance(r, Role) else Role(r) for r in roles)


def _norm_tier(tier: Tier | str) -> Tier:
    return tier if isinstance(tier, Tier) else Tier(tier)


def _entitlement_reason(
    held_roles: frozenset[Role], tier: Tier, min_tier: Tier, allowed: frozenset[Role]
) -> tuple[bool, str]:
    tier_ok = tier_meets(tier, min_tier)
    matching = sorted(r.value for r in (held_roles & allowed))
    role_ok = bool(matching)
    if tier_ok and role_ok:
        return True, f"tier {tier.value} meets minimum {min_tier.value}; role(s) {matching} permit this class"
    blockers = []
    if not tier_ok:
        blockers.append(f"tier {tier.value} is below minimum {min_tier.value}")
    if not role_ok:
        blockers.append(f"no held role in {sorted(r.value for r in allowed)}")
    return False, "; ".join(blockers)


def build_authority_graph(roles: Iterable[Role | str], tier: Tier | str) -> AuthorityGraph:
    """Build the effective-authority graph for a principal (roles, tier).

    Raises ValueError on an unknown role or tier (from the enum constructors).
    """
    held_roles = _norm_roles(roles)
    t = _norm_tier(tier)
    matrix = entitlement_matrix()
    held = set(capabilities_for(held_roles, t))

    principal_label = f"{'+'.join(sorted(r.value for r in held_roles)) or 'none'} @ {t.value}"
    nodes: list[dict] = [
        {
            "id": "principal",
            "kind": "principal",
            "label": principal_label,
            "roles": sorted(r.value for r in held_roles),
            "tier": t.value,
        }
    ]
    edges: list[dict] = []
    activity_nodes: dict[str, dict] = {}

    for cls in CapabilityClass:  # enum order, for a deterministic graph
        min_tier, allowed = matrix[cls]
        granted, reason = _entitlement_reason(held_roles, t, min_tier, allowed)
        is_held = cls.value in held  # canonical, from capabilities_for
        nodes.append(
            {
                "id": cls.value,
                "kind": "capability_class",
                "label": cls.value,
                "held": is_held,
                "min_tier": min_tier.value,
                "allowed_roles": sorted(r.value for r in allowed),
            }
        )
        edges.append(
            {"src": "principal", "dst": cls.value, "gate": "entitlement", "granted": granted, "reason": reason}
        )
        if is_held:
            act = _ACTIVITY_FOR[cls]
            activity_nodes.setdefault(act.id, act.as_node())
            edges.append({"src": cls.value, "dst": act.id, "gate": "engagement"})

    nodes.extend(activity_nodes[key] for key in sorted(activity_nodes))

    held_classes = sorted(held)
    reachable_tracks: set[str] = set()
    consequential_tokens: set[str] = set()
    for cls in CapabilityClass:
        if cls.value not in held:
            continue
        act = _ACTIVITY_FOR[cls]
        reachable_tracks.update(act.tracks)
        if act.kind is ActivityKind.CONSEQUENTIAL:
            consequential_tokens.update(act.tracks)
    reachability = {
        "held_classes": held_classes,
        "blocked_classes": sorted(c.value for c in CapabilityClass if c.value not in held),
        "target_directed_classes": sorted(
            c.value for c in CapabilityClass if c.value in held and _ACTIVITY_FOR[c].target_directed
        ),
        "analysis_classes": sorted(
            c.value for c in CapabilityClass if c.value in held and _ACTIVITY_FOR[c].kind is ActivityKind.ANALYSIS
        ),
        "consequential_classes": sorted(
            c.value
            for c in CapabilityClass
            if c.value in held and _ACTIVITY_FOR[c].kind is ActivityKind.CONSEQUENTIAL
        ),
        "reachable_tracks": sorted(reachable_tracks),
        "can_reach_consequential": bool(consequential_tokens),
        "requires_single_use_token": sorted(consequential_tokens),
    }

    return AuthorityGraph(
        roles=sorted(r.value for r in held_roles),
        tier=t.value,
        nodes=nodes,
        edges=edges,
        reachability=reachability,
    )
