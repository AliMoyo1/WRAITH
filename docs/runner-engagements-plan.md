# Runner engagements plan (server-side execution, phase 4 sub-phase 3)

Branch: `runner-engagements` off `main`. Implements section 15.3 of
docs/server-side-execution-scope.md: tenant-scoped server-side engagement records
and the durable single-use approval-token machinery, with the kernel enforcing them.

Reuses the existing kernel (`src/orchestrator/`): `Engagement` (HMAC-signed,
expiring, carries a `Scope`), `ApprovalToken` (single-use), and `Scope`/`ScopeList`.
The Runner is the only holder of the engagement signing key.

## Steps

- [ ] `runner/config.py`: `signing_key()` reading `WRAITH_RUNNER_SIGNING_KEY` (no
  default, fail closed). The Runner signs engagements and verifies approval tokens
  with it; it is distinct from the entitlement public key and the result-store key.
- [ ] `runner/models.py`: `Engagement` (id, tenant_id, created_by, scope_json,
  approved_at, expires_at, open, signature) and `ConsumedToken` (composite PK
  tenant_id + nonce, consumed_at) for durable per-tenant single use.
- [ ] `runner/repository.py`: `create_engagement`, `get_engagement` (tenant-scoped),
  `close_engagement`, and `consume_token` (atomic insert; False on replay). Every
  call bound to tenant_id.
- [ ] `runner/engagements.py`: `scope_from_spec` (build a `Scope` from a submitted
  allowlist spec), `build_engagement` (build and HMAC-sign an `orchestrator.
  Engagement`), and `engagement_from_row` (rehydrate a stored engagement to
  enforce validity). Keeps app.py lean.
- [ ] `runner/app.py`: `create_app` gains a `signing_key`. Endpoints, all
  grant-gated and tenant-scoped:
  - `POST /v1/engagements` (requires `control_plane_scan`): build a `Scope` from the
    body, mint and sign an `Engagement`, store it, return its id and expiry.
  - `GET /v1/engagements/{id}` (requires `control_plane_read`): return the
    engagement and whether the kernel currently considers it valid.
  - `POST /v1/engagements/{id}/close` (requires `control_plane_scan`): set open
    false.
- [ ] Tests: create/get/close; tenant isolation (tenant A cannot see or close
  tenant B's engagement); the capability gate (a read-only grant cannot create);
  kernel validity (valid while open and unexpired, invalid after close); and durable
  single-use tokens (a nonce consumes once per tenant, the replay is refused, the
  same nonce in another tenant is independent).

## Capability mapping

"Operator capability" in the scope note maps to `control_plane_scan` here: the class
that authorizes running scans, held by Analyst and Operator, not Viewer. Reading an
engagement needs only `control_plane_read`.

## Not in scope (later sub-phases)

`POST /v1/scans` plus the worker and per-tenant results (4); the full
verify-and-consume of a token inside a gated scan reuses `consume_token` then and is
wired in sub-phases 4 and 6; the kill-switch (5); offensive execution (6).

## Verification

ruff check src tests, mypy src, pytest -q all green. No push or merge without
explicit approval.

## Change log

- Built all steps on `runner-engagements`. Runner now has `WRAITH_RUNNER_SIGNING_KEY`,
  tenant-scoped `Engagement` and durable `ConsumedToken` models, the repository
  access, the `runner.engagements` helpers (reusing `orchestrator.Engagement`), and
  the three grant-gated, tenant-scoped endpoints. ruff clean, mypy clean (47 files),
  pytest 198 passed (4 new: create/get/close, capability gate, tenant isolation,
  durable single-use tokens).
