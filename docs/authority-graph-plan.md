# Effective-authority graph (differentiator)

## Goal

Compose WRAITH's two independent authorization axes into a single reachability
picture for a principal, so an authority review can see not just what capability
classes a principal holds, but what they can actually reach end to end and what
further context each action still requires.

The two axes today are enforced separately and there is no view that composes them:

1. Entitlement gate (`entitlement.policy`): role-by-tier matrix decides "may this
   principal use this capability class at all". `capabilities_for(roles, tier)`.
2. Engagement gate (`orchestrator.policy` / `orchestrator.engagement`): scope plus an
   open, signed, unexpired engagement gate every engine invocation; consequential
   tracks (exploitation, post-exploitation) additionally require a single-use,
   target-bound approval token.

Holding a class is necessary but never sufficient: a grant authorizes a class, never
a target. The graph makes that composition explicit and testable.

## Design

Pure analysis over the two policy models. Grants nothing, invokes nothing.

New top-level package `src/authority_graph/` (keeps the entitlement core free of any
orchestrator dependency; the graph is the composition layer that depends on both).

`build_authority_graph(roles, tier) -> AuthorityGraph` builds:

- principal node (roles, tier)
- one capability_class node per class in the matrix, with `held` and the matrix row
  (min tier, allowed roles)
- entitlement edges principal -> class, each carrying `granted` and a human reason
  (why granted, or which of tier/role blocks it)
- for each held class, an engagement edge class -> activity node
- activity nodes: control-plane (not target-directed), analysis (scope + engagement),
  consequential (scope + engagement + single-use token), administrative (not
  target-directed). Each activity node carries its engagement conditions and the
  kernel `Track` values it reaches.
- a `reachability` summary: held vs blocked classes, target-directed classes,
  analysis vs consequential classes, the union of reachable kernel tracks,
  `can_reach_consequential`, and which tracks still require a single-use token.

Class -> activity composition model (documented in the module, single source):

| capability class          | activity        | kernel tracks                         | still gated by                          |
|---------------------------|-----------------|---------------------------------------|-----------------------------------------|
| control_plane_read        | control_plane   | (none, not target-directed)           | (none)                                  |
| control_plane_scan        | analysis        | web_api, network_cloud, sast_agentic  | scope, open engagement                  |
| redteam_recon             | analysis        | web_api, network_cloud, sast_agentic  | scope, open engagement                  |
| redteam_probe             | analysis        | web_api, network_cloud, sast_agentic  | scope, open engagement                  |
| redteam_exploit           | consequential   | exploitation                          | scope, open engagement, single-use token|
| redteam_post_exploit      | consequential   | post_exploit                          | scope, open engagement, single-use token|
| admin                     | administrative  | (none, not target-directed)           | (none)                                  |

The concrete analysis track is chosen per finding by the kernel router at run time;
an analysis class reaches the analysis track set, not one fixed track.

## Files

- `src/entitlement/policy.py`: add public accessors `entitlement_matrix()` and
  `tier_meets()` (the graph needs the matrix rows and tier ranking as data, without
  reaching into module privates). Export both from `entitlement/__init__.py`.
- `src/authority_graph/graph.py` (new): the model above.
- `src/authority_graph/__init__.py` (new): export `AuthorityGraph`,
  `build_authority_graph`.
- `src/cli/wraith.py`: add `wraith entitlement graph --roles R --tier T [--json]
  [--out FILE]`, mirroring `entitlement recommend`. Text summary by default; full
  graph as JSON with `--json`.
- `tests/test_authority_graph.py` (new): reachability per principal (viewer/community,
  analyst/pro, operator/enterprise, admin/community), edge reasons, activity
  conditions, node completeness, determinism, bad-input, and the three CLI paths.

## Gates

`ruff check src tests --fix`, `mypy src`, `pytest -q` all green before commit.

## Changelog

- Plan written.
- Added `entitlement_matrix()` and `tier_meets()` public accessors to
  `entitlement/policy.py`; exported both from `entitlement/__init__.py`.
- Added `src/authority_graph/` (`graph.py`, `__init__.py`): `ActivityKind`,
  `Activity`, `AuthorityGraph`, `build_authority_graph`.
- Added `wraith entitlement graph --roles --tier [--json] [--out]` to
  `src/cli/wraith.py`.
- Added `tests/test_authority_graph.py` (13 tests).
- Gates green: ruff clean, mypy clean (58 files), pytest 273 passed.
