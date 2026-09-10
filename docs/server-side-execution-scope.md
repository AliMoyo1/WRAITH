# WRAITH Server-Side Execution (Entitlement Phase 4 Scope)

Status: DRAFT for review. Date: 2026-09-10. Owner: Ali Moyo.

Builds on the authorization kernel (`src/orchestrator/`), the engine adapters and
supervisor, the entitlement core (`src/entitlement/`), and the authority service
(`src/authority/`). This note scopes phase 4 of the entitlement rollout: moving
the kernel and engines behind an API, run server-side, per-tenant isolated, with a
kill-switch. Review before any code.

## 1. What phase 4 is

Today the kernel enforces authorization in-process in the CLI, engines run as local
subprocesses under the supervisor, and results are written to a local encrypted
store. Phase 4 exposes that as a hosted, multi-tenant execution service (the
"Runner"): a client submits a scan; the Runner enforces both gates, runs the
engines server-side in isolation, isolates results per tenant, and can be killed.

## 2. What phase 4 is NOT

- Not new detection capability. It relocates and hardens what exists; it does not
  add engines.
- Not the identity service. The authority (phase 2) stays the identity and
  entitlement issuer. The Runner is a consumer of grants, not an issuer.
- Not billing. Tier still comes from the authority via the grant.

## 3. Current state vs target

| Concern | Today (in-process CLI) | Target (Runner service) |
|---|---|---|
| Entitlement gate | not present in the kernel path | verify the grant's capability class on every request |
| Engagement gate | `Orchestrator.require_authorization` in-process, files under config/ | enforced server-side against tenant-scoped engagement records |
| Engine execution | local subprocess via the supervisor | server-side workers, isolated per run |
| Isolation | venv or container, single operator | per-tenant, hardware isolation for offensive runs |
| Results | local encrypted `ResultStore` | per-tenant encrypted store, retrievable by API |
| Kill-switch | a local `.killed` flag file | per-tenant and global control-plane operation |

## 4. Key architectural decisions (with recommendations)

These are the forks to settle before building. Recommendations are noted; confirm
or change them.

### 4.1 A separate Runner service, not an extension of the authority

Recommended: a distinct service. The authority is pure-Python identity and stays
portable; the Runner carries the offensive engines and the isolation infrastructure
(x86_64 Linux plus KVM for CubeSandbox), which the identity service must not host.
Separation also contains blast radius: a compromise of the Runner must not reach
the identity or the entitlement signing key.

### 4.2 Grants must become asymmetrically signed

This is the load-bearing change. Today a `CapabilityGrant` is HMAC-signed with the
shared `WRAITH_ENTITLEMENT_KEY`. For the Runner to verify a grant, it would need
that same secret, which widens the key's exposure to the most attackable service.

Recommended: move `CapabilityGrant` to an asymmetric signature (Ed25519). The
authority holds the private key and signs; the Runner (and any verifier) holds only
the public key and verifies. The signing surface stays in one place. This is a
backward-incompatible change to the grant format and to `require_entitlement`, so
it lands first, behind the existing tests.

### 4.3 Engagements become tenant-scoped server records

Today an engagement is a local signed JSON file. Server-side it becomes a
tenant-scoped record, created by a principal who holds the Operator capability and
carries scope, expiry, and (for gated actions) the approval-token machinery. The
Runner enforces it. Approval tokens stay single-use, now tracked per tenant in the
Runner's store rather than a local file.

## 5. The two-gate enforcement, server-side

Every Runner request that executes an engine passes both gates, in order:

```
request: bearer grant + engagement id + target + track/capability (+ token for gated)
  |
  v
[ Entitlement gate ]  verify the grant (Ed25519, unexpired) and that it carries the
  required capability class (CONTROL_PLANE_SCAN for defensive; REDTEAM_* for offensive)
  |  deny -> 403
  v
[ Engagement gate ]   the kernel: the engagement is open, valid, and tenant-owned;
  the target is in its scope; a gated action additionally consumes a single-use token
  |  deny -> refuse
  v
[ Tenant isolation ]  the engagement, target scope, and result destination all belong
  to the grant's tenant; nothing crosses tenants
  |
  v
run the engine(s) server-side, isolated
```

The bright line is unchanged: the grant authorizes a capability class; the target
still needs the engagement, scope, and token. A subscription never authorizes a
target.

## 6. Engine execution and isolation

- The supervisor (bounded concurrency, per-job failure isolation, order-preserving)
  moves server-side and runs inside a worker, not the request handler.
- Defensive engines (SkillSpector-class, target-read-only static analysis) run in a
  container with dropped capabilities.
- Offensive engines (Strix-class, and later exploitation) run in hardware isolation
  (CubeSandbox on x86_64 Linux plus KVM), one sandbox per run, torn down after.
- Every run is labelled with its tenant and engagement; a worker only ever handles
  one tenant's run at a time and writes only into that tenant's result space.

## 7. Asynchronous execution

Scans are long-running, so the API does not block on them.

Recommended: a job queue with dedicated workers. `POST /v1/scans` enqueues a job and
returns a scan id immediately; workers pull jobs, run the supervisor, and write
findings; `GET /v1/scans/{id}` reports status and results. Durability (a job
survives a worker restart) and isolation (a worker runs one tenant's job) both argue
for a real queue over in-process background tasks.

## 8. Kill-switch

- Global operator kill: halts all running jobs and refuses new ones, service-wide
  (the platform-level emergency stop).
- Per-tenant kill: halts a tenant's running jobs without affecting others.
- Enforced in the worker loop (a running engine is signalled and its sandbox torn
  down) and at intake (new jobs refused while killed). This generalizes the current
  in-process kill flag to a control-plane state.

## 9. Data model additions (Runner, per tenant)

- `engagement(id, tenant_id, created_by, scope, approved_at, expires_at, open, signature)`
- `approval_token_consumed(tenant_id, nonce, consumed_at)` for durable single use
- `scan(id, tenant_id, engagement_id, target, track, status, created_at, finished_at)`
- results: per-tenant encrypted finding storage, keyed per tenant and engagement,
  with the existing hash-chained audit trail

## 10. Runner API surface (v1)

Public:
- `GET /v1/healthz`

Engagements (Operator capability, tenant-scoped):
- `POST /v1/engagements` (create), `GET /v1/engagements/{id}`, `POST /v1/engagements/{id}/close`

Scans (grant-gated; capability class by track):
- `POST /v1/scans` (enqueue: engagement id, target, track; token for a gated track)
- `GET /v1/scans/{id}` (status and findings)
- `GET /v1/scans` (list the tenant's scans)

Control:
- `POST /v1/kill` (per-tenant; global requires a platform-operator grant)

Every non-public endpoint requires a valid grant carrying the right capability
class, and every operation is scoped to the grant's tenant.

## 11. Results and evidence

Findings are stored per tenant, encrypted, with the audit chain and tip anchor that
already exist in the result store, extended with a tenant dimension. Signed evidence
bundles (engine digests, the policy decision, completeness, the entitlement and
engagement records) feed ThemisIQ over the existing one-way signed feed. No identity
crosses that boundary.

## 12. Security and threat model

Defends:
- Cross-tenant execution or result access: tenant is derived from the grant, checked
  on every engagement, target, worker, and result path, with cross-tenant tests.
- Entitlement or engagement bypass: both gates enforced server-side; neither is
  inferable from client input.
- Key exposure: with asymmetric grants the Runner never holds the signing secret.
- Offensive blast radius: hardware isolation per run, plus the kill-switch.

Known risks to manage:
- The Runner is the highest-value target (it runs offensive tooling with network
  reach). It must be the most hardened surface, on isolated infrastructure.
- Sandbox escape is the worst case; CubeSandbox on KVM is the mitigation, and gated
  actions still require the engagement plus a single-use token.
- Worker starvation or a runaway job: bounded concurrency, per-job timeouts, and the
  kill-switch.

## 13. Host and deployment requirements

- The Runner and its offensive workers require x86_64 Linux with KVM (CubeSandbox).
  Defensive-only workers can run in plain containers.
- Deployed separately from both the authority and ThemisIQ, behind a TLS-terminating
  proxy, with the queue and per-tenant result storage as managed dependencies.
- Secrets: the grant public key (verify only), the result-store master key, and the
  engagement signing key, from a secrets manager. The grant private key lives only in
  the authority.

## 14. Open questions

1. Confirm a separate Runner service (recommended) versus extending the authority.
2. Confirm moving `CapabilityGrant` to Ed25519 (recommended). This is a prerequisite
   and is the first sub-phase.
3. Queue and worker technology (a managed queue versus a self-hosted one).
4. Do engagements live in the Runner, or in a shared control-plane service the
   authority and Runner both use?
5. Offensive execution in v1, or defensive-only server-side first with offensive
   behind a later gate?
6. Result retention and export policy per tenant.

## 15. Sub-rollout (phase 4 as several green PRs)

1. Asymmetric grants: move `CapabilityGrant` to Ed25519; the authority signs with a
   private key, verifiers use the public key; update `require_entitlement` and the
   authority. Security-bearing, lands first.
2. Runner skeleton: the service, tenant-scoped storage, `GET /v1/healthz`, grant
   verification middleware (public key), and the capability-class check, with an
   isolation test.
3. Engagements server-side: tenant-scoped engagement records and the token machinery
   (durable single-use), with the kernel enforcing them.
4. Defensive scans end-to-end: `POST /v1/scans` for a target-read-only track, the
   worker running the supervisor in a container, per-tenant encrypted results, and
   `GET /v1/scans/{id}`.
5. Kill-switch: per-tenant and global.
6. Offensive execution: gated tracks with hardware isolation (CubeSandbox), behind
   the engagement plus single-use token and the REDTEAM capability classes.

Recommended: start with sub-phase 1 (asymmetric grants), since every later sub-phase
depends on the Runner being able to verify a grant without the signing secret.
