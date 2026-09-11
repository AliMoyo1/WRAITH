# Runner offensive execution plan (server-side execution, phase 4 sub-phase 6)

Branch: `runner-offensive` off `main`. Implements section 15.6: offensive execution
behind the engagement plus a single-use token and the REDTEAM capability classes,
with hardware isolation.

Scoped (agreed 2026-09-11): build and test the parts that are real here, the
token-gated offensive scan path, the REDTEAM capability gate, offensive tracks
requiring a single-use token, and the sandbox as an injectable boundary that fails
closed. The live CubeSandbox integration (x86_64 Linux + KVM, a pinned image) and the
real offensive engine adapters (SQLMap, ZAP active) are deployment / engine-plan
follow-ons; CI cannot exercise them.

## The gate (per offensive scan)

1. Entitlement gate: the grant carries the track's REDTEAM capability class
   (`redteam_exploit` for the `exploit` track).
2. Engagement gate: the engagement is open and valid and the target is in scope
   (as for defensive scans).
3. Token gate (consequential): the request carries a single-use approval token; the
   Runner verifies it (signature under the engagement key, bound to this engagement,
   action, and target, unexpired) and consumes it durably (`consume_token` from
   sub-phase 3). A replayed or mismatched token is refused.
4. Isolation: the offensive engines run only inside the sandbox. If the sandbox is
   unavailable, the scan fails closed and no engine runs.

The bright line holds: the grant authorizes the capability class; the engagement,
scope, and single-use token authorize this target now.

## Steps

- [ ] `runner/tokens.py`: `consume_approval_token` (verify + bind-check + durable
  consume, reusing `orchestrator.ApprovalToken` and `repository.consume_token`).
- [ ] `runner/worker.py`: a `Sandbox` boundary and `CubeSandbox` (reports unavailable
  here, so offensive engines never run outside isolation); `run_scan` gains a
  `sandbox` and runs offensive adapters through it, failing closed when unavailable.
- [ ] `runner/app.py`: `ScanCreate` gains an optional `token`; the `exploit` track
  requires `redteam_exploit` and a token; `create_app` gains an injectable `sandbox`;
  `POST /v1/scans` runs the token gate for gated tracks and routes them through the
  sandbox.
- [ ] Tests: an offensive scan with a valid token runs in the (fake) sandbox and
  returns findings; it is refused without a token, with a replayed token, with a
  token bound to the wrong target/engagement/action, and without the
  `redteam_exploit` capability; and it fails closed when the sandbox is unavailable.
  Defensive scans are unchanged.

## Not in scope (follow-ons)

The live CubeSandbox integration on KVM with a pinned image digest, and the real
offensive engine adapters (SQLMap, ZAP active) from the engine-integration plan.
`default_adapters` returns no engines for offensive tracks until those adapters land;
the framework here is proven with injected fakes.

## Verification

ruff check src tests, mypy src, pytest -q all green. No push or merge without
explicit approval.

## Change log

- Built the framework on `runner-offensive`: `runner/tokens.py` (consume_approval_token),
  `Sandbox`/`CubeSandbox` and a sandboxed `run_scan` in the worker, and the `exploit`
  track in the app (redteam_exploit capability + single-use token + sandbox routing).
  ruff clean, mypy clean (49 files), pytest 216 passed (6 new: valid-token run in the
  fake sandbox, missing token, replayed token, wrong-target token, missing
  redteam_exploit, and fail-closed when the sandbox is unavailable). Live CubeSandbox
  and the real offensive adapters remain follow-ons. Completes the phase-4 sub-rollout.
