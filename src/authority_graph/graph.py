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

The graph distinguishes four layers of authority, so it reports what a principal can
actually do rather than only what policy would allow:

* eligible: the role-by-tier matrix would grant the class to this principal.
* held: the actual (verified) grant carries the class. A capped API-key grant, or any
  excluded class, holds fewer than it is eligible for; the gap is surfaced.
* conditionally reachable: a held, target-directed class whose engagement-gate
  conditions (scope, open engagement, and for consequential actions a single-use token)
  are not yet satisfied by the supplied runtime context.
* currently authorized: a held class that is authorized right now, either because it is
  not target-directed or because the runtime context satisfies its conditions.

Given only (roles, tier) it runs in policy mode: held equals eligible and, with no
runtime context, only non-target-directed classes are currently authorized. Given a
real signed grant (and optionally a public key to verify it, plus an
``AuthorizationContext``), it reports the grant's actual held set and, for a target, what
is authorized now.

Pure analysis over the policy and kernel models. It grants nothing and invokes nothing.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from entitlement import CapabilityGrant
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
    CONTROL_PLANE = "control_plane"      # platform read/authoring; not target-directed
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
_ENGAGE_AUTHORING = Activity(
    "activity:engagement_authoring", ActivityKind.CONTROL_PLANE, "Engagement authoring", ()
)
_ANALYSIS = Activity("activity:analysis", ActivityKind.ANALYSIS, "Engine analysis", _ANALYSIS_TRACKS)
_EXPLOITATION = Activity(
    "activity:exploitation", ActivityKind.CONSEQUENTIAL, "Exploitation", (Track.EXPLOITATION.value,)
)
_POST_EXPLOIT = Activity(
    "activity:post_exploit", ActivityKind.CONSEQUENTIAL, "Post-exploitation", (Track.POST_EXPLOIT.value,)
)
_ADMINISTRATION = Activity("activity:administration", ActivityKind.ADMINISTRATIVE, "Tenant administration", ())

# capability class -> the activity it drives. The single source of the composition
# model between the two axes (see docs/authority-graph-plan.md). Engagement authoring is
# a control-plane action (it produces the engagement rather than running against a
# target), so it is not target-directed and carries no engagement-gate conditions.
_ACTIVITY_FOR: dict[CapabilityClass, Activity] = {
    CapabilityClass.CONTROL_PLANE_READ: _CONTROL_PLANE,
    CapabilityClass.CONTROL_PLANE_SCAN: _ANALYSIS,
    CapabilityClass.CONTROL_PLANE_ENGAGE: _ENGAGE_AUTHORING,
    CapabilityClass.REDTEAM_RECON: _ANALYSIS,
    CapabilityClass.REDTEAM_PROBE: _ANALYSIS,
    CapabilityClass.REDTEAM_EXPLOIT: _EXPLOITATION,
    CapabilityClass.REDTEAM_POST_EXPLOIT: _POST_EXPLOIT,
    CapabilityClass.ADMIN: _ADMINISTRATION,
}


@dataclass(frozen=True)
class AuthorizationContext:
    """Runtime authorization facts used to compute "currently authorized".

    These are observed by the caller (the Runner has them; a CLI supplies what it knows).
    All default to the unsatisfied state, so with no context only non-target-directed
    held classes are currently authorized. They describe one target at a time.
    """

    engagement_valid: bool = False   # an open, signed, unexpired engagement exists
    target: str | None = None
    target_in_scope: bool = False    # that engagement's scope allows the target
    has_valid_token: bool = False    # a valid single-use token for the target and action


@dataclass
class AuthorityGraph:
    """A principal's effective authority as a graph of nodes and gated edges."""

    roles: list[str]
    tier: str
    nodes: list[dict]
    edges: list[dict]
    reachability: dict
    grant_verified: bool | None = None
    principal_id: str | None = None
    tenant_id: str | None = None

    def to_dict(self) -> dict:
        principal: dict = {"roles": self.roles, "tier": self.tier}
        if self.principal_id is not None:
            principal["principal_id"] = self.principal_id
        if self.tenant_id is not None:
            principal["tenant_id"] = self.tenant_id
        if self.grant_verified is not None:
            principal["grant_verified"] = self.grant_verified
        return {
            "principal": principal,
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


def _currently_authorized(act: Activity, ctx: AuthorizationContext) -> bool:
    """Whether a held class's activity is authorized right now under the context."""
    if not act.target_directed:
        return True  # control-plane / admin / engagement authoring need no engagement
    if act.kind is ActivityKind.CONSEQUENTIAL:
        return ctx.engagement_valid and ctx.target_in_scope and ctx.has_valid_token
    return ctx.engagement_valid and ctx.target_in_scope  # analysis


def build_authority_graph(
    roles: Iterable[Role | str] | None = None,
    tier: Tier | str | None = None,
    *,
    grant: CapabilityGrant | None = None,
    public_key: bytes | None = None,
    context: AuthorizationContext | None = None,
) -> AuthorityGraph:
    """Build the effective-authority graph for a principal.

    Policy mode: pass ``roles`` and ``tier``; held equals eligible. Grant mode: pass a
    real ``grant`` (its roles, tier, and capabilities are used); pass ``public_key`` to
    verify it (a grant that does not verify raises ValueError, fail closed). Pass a
    ``context`` to compute what is currently authorized for a target.

    Raises ValueError on an unknown role or tier, on a grant that fails verification, or
    when neither a grant nor (roles, tier) is provided.
    """
    ctx = context or AuthorizationContext()
    grant_verified: bool | None = None
    principal_id: str | None = None
    tenant_id: str | None = None

    if grant is not None:
        if public_key is not None:
            grant_verified = grant.verify(public_key) and not grant.is_expired()
            if not grant_verified:
                raise ValueError("grant does not verify against the provided public key")
        held_roles = _norm_roles(grant.roles)
        t = _norm_tier(grant.tier)
        eligible = set(capabilities_for(grant.roles, grant.tier))
        held = set(grant.capabilities)  # the actual set the (verified) grant carries
        principal_id = grant.principal_id
        tenant_id = grant.tenant_id
    else:
        if roles is None or tier is None:
            raise ValueError("provide a grant, or both roles and tier")
        held_roles = _norm_roles(roles)
        t = _norm_tier(tier)
        eligible = set(capabilities_for(held_roles, t))
        held = set(eligible)  # policy mode: the grant is exactly the policy set

    matrix = entitlement_matrix()
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
        is_eligible, reason = _entitlement_reason(held_roles, t, min_tier, allowed)
        is_held = cls.value in held
        nodes.append(
            {
                "id": cls.value,
                "kind": "capability_class",
                "label": cls.value,
                "eligible": is_eligible,
                "held": is_held,
                "min_tier": min_tier.value,
                "allowed_roles": sorted(r.value for r in allowed),
            }
        )
        edges.append(
            {
                "src": "principal",
                "dst": cls.value,
                "gate": "entitlement",
                "granted": is_eligible,
                "reason": reason,
            }
        )
        if is_held:
            act = _ACTIVITY_FOR[cls]
            activity_nodes.setdefault(act.id, act.as_node())
            edges.append(
                {
                    "src": cls.value,
                    "dst": act.id,
                    "gate": "engagement",
                    "currently_authorized": _currently_authorized(act, ctx),
                }
            )

    nodes.extend(activity_nodes[key] for key in sorted(activity_nodes))

    held_matrix = [c for c in CapabilityClass if c.value in held]
    reachable_tracks: set[str] = set()
    consequential_tokens: set[str] = set()
    for cls in held_matrix:
        act = _ACTIVITY_FOR[cls]
        reachable_tracks.update(act.tracks)
        if act.kind is ActivityKind.CONSEQUENTIAL:
            consequential_tokens.update(act.tracks)

    currently_authorized = sorted(
        c.value for c in held_matrix if _currently_authorized(_ACTIVITY_FOR[c], ctx)
    )
    conditionally_reachable = sorted(
        c.value
        for c in held_matrix
        if _ACTIVITY_FOR[c].target_directed and not _currently_authorized(_ACTIVITY_FOR[c], ctx)
    )
    reachability = {
        "eligible_classes": sorted(eligible),
        "held_classes": sorted(held),
        "blocked_classes": sorted(c.value for c in CapabilityClass if c.value not in eligible),
        "excluded_by_grant": sorted(eligible - held),
        "target_directed_classes": sorted(
            c.value for c in held_matrix if _ACTIVITY_FOR[c].target_directed
        ),
        "analysis_classes": sorted(
            c.value for c in held_matrix if _ACTIVITY_FOR[c].kind is ActivityKind.ANALYSIS
        ),
        "consequential_classes": sorted(
            c.value for c in held_matrix if _ACTIVITY_FOR[c].kind is ActivityKind.CONSEQUENTIAL
        ),
        "conditionally_reachable": conditionally_reachable,
        "currently_authorized": currently_authorized,
        "reachable_tracks": sorted(reachable_tracks),
        "can_reach_consequential": bool(consequential_tokens),
        "requires_single_use_token": sorted(consequential_tokens),
        "context": {
            "engagement_valid": ctx.engagement_valid,
            "target": ctx.target,
            "target_in_scope": ctx.target_in_scope,
            "has_valid_token": ctx.has_valid_token,
        },
    }

    return AuthorityGraph(
        roles=sorted(r.value for r in held_roles),
        tier=t.value,
        nodes=nodes,
        edges=edges,
        reachability=reachability,
        grant_verified=grant_verified,
        principal_id=principal_id,
        tenant_id=tenant_id,
    )
