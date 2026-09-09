# WRAITH Entitlement Layer (RBAC and Subscription)

Status: DRAFT for review. Date: 2026-09-09. Owner: Ali Moyo.

This note pins the design of WRAITH's entitlement subsystem before any code is
written. It is a design contract, not an implementation. Review and adjust the
roles, tiers, matrix, and open questions here; the build follows the agreed
version.

## 1. Decision this implements

WRAITH ships two surfaces, and users reach them by entitlement:

1. The evidence-first Agent Security Control Plane (defensive).
2. The Red Team Annex (offensive), the surface those entitlements unlock.

Access is granted by RBAC role plus subscription tier. Identity, roles, and
subscription are WRAITH-native and kept SEPARATE from ThemisIQ. ThemisIQ remains
a one-way consumer of signed findings; there is no shared identity, SSO, or
billing between the two products.

Deployment model (decided 2026-09-09): WRAITH is a HOSTED, MULTI-TENANT online
service. Principals authenticate to the WRAITH authority over the network (online
login: WRAITH-native email and password, MFA required for Operator and Admin,
plus API keys or bearer tokens for automation, all over HTTPS) and receive a
short-lived signed grant; there is no offline grant file in the product path. The
authority holds the entitlement key server-side, RUNS the engines server-side
(thin client), and is the single enforcement point for both the entitlement gate
and the engagement gate.

## 2. Purpose and non-goals

In scope:

- A WRAITH-native notion of principal (user), tenant, role, and subscription tier.
- A signed, expiring capability grant that says which capability classes a
  principal may use.
- Verification of that grant at every enforcement point, fail closed.

Explicit non-goals:

- This is NOT authorization to attack a target. A subscription unlocks a
  feature; it never grants permission to run against a specific target. That
  permission always comes from the existing kernel gate (scope plus a signed,
  unexpired engagement, plus a single-use approval token for gated actions),
  regardless of tier.
- This is NOT a ThemisIQ integration. No shared accounts. If a customer uses
  both products they hold two accounts. Federation is out of scope for now.
- This is NOT DRM against a self-hoster. Because the product is hosted, the key
  stays server-side; see section 15.

## 3. Invariants (the bright lines)

1. Entitlement is a separate axis from engagement authorization. Both must pass.
   Entitlement never substitutes for, weakens, or short-circuits the kernel gate.
2. A subscription buys access to the tool, never authorization against a target.
3. Fail closed. Missing, unreadable, expired, or unverifiable entitlement means
   deny.
4. Entitlement is authority-issued and cryptographically verified, never trusted
   from a client-side flag or a hidden CLI subcommand. Hiding UI is presentation,
   not enforcement.
5. Entitlement has its own signing key, distinct from `WRAITH_SIGNING_KEY`
   (engagements) and `WRAITH_RESULT_KEY` (result store).
6. Every entitlement decision is logged through the redacting logger and is
   available as evidence.
7. Tenant isolation: every resource (grants, engagements, scope, results,
   findings, audit) is tenant-bound. No request may read or act across tenants.
   The server enforces this on every call, fail closed, independent of the
   capability check.

## 4. Two authorization axes

A gated request must clear both gates, in this order:

```
request (principal + capability class + target + action)
  |
  v
[ Entitlement gate ]   may THIS principal use THIS capability class at all?
  role x tier -> allowed classes, from a signed CapabilityGrant
  |  deny -> refuse, logged
  v
[ Engagement gate ]    may THIS target/action run right now?
  kernel: scope + signed engagement (+ single-use token for gated actions)
  |  deny -> refuse, logged
  v
allowed: run
```

The entitlement gate is coarse and per principal. The engagement gate is fine
and per operation. Neither replaces the other. In the hosted model both gates
are enforced server-side.

## 5. Domain model

- Principal: a WRAITH user identity (`principal_id`), belonging to one tenant.
- Tenant: an account or organization (`tenant_id`). All grants and all resources
  are tenant-bound.
- Role: one or more of Viewer, Analyst, Operator, Admin (see section 6). A
  principal may hold more than one role; effective role rights are the union.
- Tier: the tenant subscription level, one of Community, Pro, Enterprise
  (see section 7).
- CapabilityClass: a coarse permission unit that maps onto the taxonomy and the
  annex (see section 8).
- CapabilityGrant: the signed claim that carries the above and the computed set
  of allowed capability classes (see section 10).

## 6. Roles (proposed defaults)

| Role | Purpose |
|---|---|
| Viewer | Read findings, reports, Agent BOM, and the authority graph. No runs. |
| Analyst | Everything Viewer can do, plus run defensive scans and red team recon and probe. |
| Operator | Everything Analyst can do, plus red team exploit and post-exploit (still gated by the kernel). |
| Admin | Manage the tenant: principals, roles, engagements, and scope. Read access. Not automatically Operator (separation of duties). |

Note the separation of duties: an Admin manages the tenant but is not
automatically allowed to run exploitation. To do both, a principal holds Admin
and Operator.

## 7. Tiers (proposed defaults)

| Tier | Unlocks (maximum capability classes available) |
|---|---|
| Community | Control plane read and defensive scan. Defensive only. |
| Pro | Community, plus red team recon and probe. |
| Enterprise | Pro, plus red team exploit and post-exploit. |

## 8. Capability classes

Capability classes are the unit the grant carries and the enforcement points
check. They map onto the frozen taxonomy layers and the annex phases.

| Capability class | Maps to | Notes |
|---|---|---|
| CONTROL_PLANE_READ | reports, Agent BOM, authority graph, stored findings | read-only |
| CONTROL_PLANE_SCAN | defensive scanning (layers 6 and 7 today) | still requires scope |
| REDTEAM_RECON | annex recon (layers 0 and 1) | requires an engagement |
| REDTEAM_PROBE | annex probe (layers 2 to 7) | requires an engagement |
| REDTEAM_EXPLOIT | annex exploit (layer 8, annex `gated: true`) | also requires a single-use token |
| REDTEAM_POST_EXPLOIT | annex post-exploit (layer 9, annex `gated: true`) | also requires a single-use token |
| ADMIN | manage principals, roles, engagements, scope | tenant administration |

The annex already marks exploit and post-exploit capabilities `gated: true` in
`config/redteam_capabilities.yaml`. Such a capability is double-gated, and the
two gates answer two different questions:

- The grant gate asks: may this principal use this capability class at all? For a
  `gated: true` capability the matching class (REDTEAM_EXPLOIT or
  REDTEAM_POST_EXPLOIT) must be present in the grant, which per section 9 means
  the tenant is at Enterprise tier and the principal holds the Operator role.
- The kernel gate asks: may it run against THIS target right now? That is the
  existing scope plus signed engagement plus single-use approval token check.

Both must pass, and they are independent: the grant never authorizes a target,
and the token never grants a capability class. A `gated: true` capability must
never be reachable without the entitlement class and the kernel token together.

## 9. Entitlement matrix

A request for a capability class is entitled when the tenant tier is at least the
minimum tier AND the principal holds at least one allowed role.

| Capability class | Minimum tier | Roles allowed |
|---|---|---|
| CONTROL_PLANE_READ | Community | Viewer, Analyst, Operator, Admin |
| CONTROL_PLANE_SCAN | Community | Analyst, Operator |
| REDTEAM_RECON | Pro | Analyst, Operator |
| REDTEAM_PROBE | Pro | Analyst, Operator |
| REDTEAM_EXPLOIT | Enterprise | Operator |
| REDTEAM_POST_EXPLOIT | Enterprise | Operator |
| ADMIN | Community | Admin |

The authority computes a principal's granted classes as the set of classes whose
minimum tier is met by the tenant and whose allowed roles intersect the
principal's roles. That computed set is written into the grant, so policy stays
server-side and the client and kernel only check membership.

## 10. The CapabilityGrant claim

A grant mirrors the existing signed-authorization objects (`Engagement`,
`ApprovalToken`): a canonical payload plus an HMAC-SHA256 signature.

Fields:

- `version`: schema version.
- `tenant_id`: the account the grant is bound to.
- `principal_id`: the user the grant is issued to.
- `roles`: the principal's roles at issue time.
- `tier`: the tenant tier at issue time.
- `capabilities`: the explicit list of granted capability classes (computed by
  the authority per section 9).
- `issued_at`, `expires_at`: ISO 8601. Grants are short-lived and renewable, not
  single-use (unlike approval tokens).
- `nonce`: random, for audit correlation and future revocation lists.
- `signature`: HMAC-SHA256 over the canonical payload, keyed by the entitlement
  key.

Issuance: only the authority (holder of the entitlement key) can mint a grant.
It authenticates the principal, resolves roles and the tenant tier, computes the
capability set, and signs.

Verification (at every enforcement point): the signature is valid under the
entitlement key, the grant is not expired, `tenant_id` and `principal_id` are
present, and the requested capability class is in `capabilities`. Any failure is
a deny.

## 11. Enforcement

Proposed code layout (mirrors the `orchestrator` package style):

- `src/entitlement/grant.py`: the `CapabilityGrant` dataclass with `sign`,
  `verify`, `is_expired`, `to_dict`, `from_dict`. Standard library only, like
  `engagement.py`.
- `src/entitlement/policy.py`: the `CapabilityClass` enum, the role-by-tier
  matrix, `capabilities_for(roles, tier)` (authority side), and
  `require_entitlement(grant, capability_class, key)` (verifier side, raises on
  deny).
- `src/config.py`: `entitlement_key()` reading `WRAITH_ENTITLEMENT_KEY` with no
  default, plus grant serialization helpers, following the existing patterns.

Wiring: each entitled action names the capability class it needs and calls
`require_entitlement` BEFORE the kernel's `require_authorization`.

| Action | Capability class |
|---|---|
| scan | CONTROL_PLANE_SCAN |
| report | CONTROL_PLANE_READ |
| redteam recon or probe | REDTEAM_RECON or REDTEAM_PROBE |
| redteam authorize and exploit generate | REDTEAM_EXPLOIT |
| redteam authorize and post-exploit generate | REDTEAM_POST_EXPLOIT |
| engage, scope | ADMIN |

Delivery: the active grant is obtained by online login. A client authenticates
to the WRAITH authority, which returns a short-lived signed grant that the client
caches and refreshes on expiry. The authority holds the entitlement key; clients
never see it. Enforcement and engine execution are server-side (the client is
thin). Fail closed: no valid grant means deny for every class except, optionally,
a small public surface (see section 16).

## 12. Separation from ThemisIQ

- No shared identity, SSO, or billing. WRAITH principals and tenants are WRAITH's
  own.
- The only link is the existing one-way feed of signed findings from WRAITH to
  ThemisIQ. That feed carries no identity or entitlement.
- A customer using both products holds two accounts. Any future federation is a
  separate, explicit decision and is out of scope here.

## 13. Key management

- `WRAITH_ENTITLEMENT_KEY`: the entitlement signing key. No default. A missing
  key fails closed at both issuance and verification.
- Distinct from `WRAITH_SIGNING_KEY` and `WRAITH_RESULT_KEY`. Keys are not reused
  across purposes.
- Hosted (the product path): the entitlement key lives only in the authority
  service. Clients receive signed grants and never see the key.
- Self-host is not the product path. If it is ever offered, a customer-scoped
  authority holds the key, with the trust trade-off noted in section 15.
- Rotation: grants are short-lived, so key rotation is handled by re-issuing
  grants under the new key.

## 14. Audit and evidence

Every entitlement decision (grant presented, class requested, allow or deny,
principal, tenant, grant nonce) is logged through the redacting JSON logger.
Allowed gated actions are already recorded in the encrypted result store and
audit chain; the entitlement decision is added to that record so an engagement's
evidence answers who was entitled to run what, under which tier and tenant, at
the time.

## 15. Threat model and honest limitations

Defends against:

- Client-side tampering: the grant is signed; edits fail verification.
- Tier or role bypass: the kernel checks the granted capability set, not a
  client flag.
- Cross-tenant use: grants are `tenant_id`-bound, and the server independently
  enforces tenant isolation on every resource (invariant 7).
- Stale access: grants expire.

Known limitations, stated plainly:

- Because the product is hosted, the entitlement key stays server-side and
  clients never hold it, so client-side self-issuance is not a path in the
  product. It would apply only to a hypothetical self-host build, which is not
  the product path.
- This layer is not the target-authorization gate and never replaces the
  engagement, scope, and token checks.
- Revocation before expiry needs either a short time-to-live or an online
  revocation check. The first version relies on short TTL; a revocation list is
  a later addition.
- Multi-tenant isolation is now the primary new risk surface. It must be enforced
  server-side on every call, not inferred from the grant alone, and covered by
  cross-tenant refusal tests.

## 16. Open questions

Resolved 2026-09-09:

- Tenancy: MULTI-TENANT from the start.
- Grant delivery: ONLINE LOGIN against a hosted authority, with refresh.
- Authentication: WRAITH-native email and password, MFA required for Operator and
  Admin, plus API keys or bearer tokens for automation, all over HTTPS.
- Execution: SERVER-SIDE. The hosted server runs the engines behind the API; the
  client is thin. Enforcement and execution are server-side, with offensive
  actions isolated (for example via CubeSandbox on Linux plus KVM).
- Revocation: SHORT TTL to start. Grants are short-lived and simply expire; a
  revocation list is deferred to a later phase.
- Roles: CONFIRMED. Viewer, Analyst, Operator, Admin, keeping the
  separation-of-duties stance (Admin is not automatically Operator).
- Tiers: CONFIRMED. Community, Pro, Enterprise. Pricing is a separate product
  decision.

Still to confirm before build:

1. Default-deny surface: which endpoints, if any, respond with no grant at all
   (for example a health check, or a capability listing that shows only names).
   This is a phase 2 (authority service) concern, not a phase 1 blocker.

## 17. Phased rollout

1. Enforcement core (security-bearing, lands first, server-agnostic):
   `CapabilityClass`, the matrix, `CapabilityGrant` sign and verify,
   `entitlement_key`, and `require_entitlement`, with tests including refusal
   proofs. This is the shared primitive both the client and the authority need,
   and it does not depend on the execution model.
2. Authority service (hosted, multi-tenant): authenticates principals, resolves
   roles and the tenant tier, and issues short-lived signed grants over HTTPS.
   Introduces the tenant and principal model and tenant-isolated storage. Holds
   the entitlement key server-side.
3. Online login and client: a client authenticates to the authority, receives a
   grant, caches it, and refreshes on expiry.
4. Server-side enforcement and execution: the kernel and engines run behind the
   API with per-tenant isolation, kill-switch, and audit. Each entitled action
   checks its capability class before the kernel gate.
5. Subscription and billing: feed the tier into issuance from the billing source.

Enforcement lands before any UI, so gating is real from the first step, never a
hidden button.
