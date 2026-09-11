# Runner scans plan (server-side execution, phase 4 sub-phase 4)

Branch: `runner-scans` off `main`. Implements section 15.4: defensive scans
end-to-end. `POST /v1/scans` enqueues a job that runs the engines server-side
through the supervisor, writes findings to a per-scan encrypted store, and
`GET /v1/scans/{id}` returns status and findings. Both gates and tenant isolation
are enforced.

Decided: an in-process worker (no external queue yet). The executor is injectable,
so tests run inline and production runs on a small thread pool; a durable queue can
replace the worker later without changing the API. Defensive-only: the `sast` track
(target-read-only static engines) is the only supported track this sub-phase.

## Two-gate enforcement (per request)

1. Entitlement gate: a valid grant that carries the track's capability class
   (`control_plane_scan` for the defensive `sast` track).
2. Engagement gate: the engagement (by id, tenant-scoped) is open and valid (kernel
   `is_valid`), and the target is in its scope.
3. Tenant isolation: the engagement, the scan row, and the result store all belong
   to the grant's tenant (the engagement/scan lookups are tenant-scoped; the store
   key is derived per scan id).

## Steps

- [ ] `runner/config.py`: `result_key()` (`WRAITH_RUNNER_RESULT_KEY`, no default),
  `results_root()` and `engines_dir()` (paths with sensible defaults).
- [ ] `runner/models.py`: add `Scan.finished_at` (nullable).
- [ ] `runner/repository.py`: `set_scan_status`.
- [ ] `runner/worker.py`: `InlineExecutor` / `BackgroundExecutor`, `run_scan` (runs
  the supervisor, writes findings to a per-scan `ResultStore`, updates the scan
  status), and `default_adapters(track, engines_dir)` for the defensive engines.
- [ ] `runner/app.py`: `create_app` gains `result_key`, `result_root`, `executor`,
  and an injectable `adapters_for`. `POST /v1/scans` (entitlement + engagement gates,
  enqueue) and `GET /v1/scans/{id}` (status + findings).
- [ ] Tests: a scan runs end-to-end (inline executor + fake adapter) and its findings
  come back; the entitlement gate refuses a read-only grant; the engagement gate
  refuses an out-of-scope target and a closed engagement; tenant isolation refuses a
  scan under another tenant's engagement; an unsupported track is rejected.

## Not in scope (later sub-phases)

The kill-switch (5); offensive tracks and hardware isolation (6); a durable external
queue (the in-process worker is deliberate for now). Gated-track scans that consume a
single-use token reuse `consume_token` (sub-phase 3) when offensive execution lands.

## Verification

ruff check src tests, mypy src, pytest -q all green. No push or merge without
explicit approval.

## Change log

- Built all steps on `runner-scans`. Runner now has the result-store key/dir config,
  `Scan.finished_at`, `set_scan_status`, the in-process worker (Inline/Background
  executor, `run_scan`, `default_adapters`), and `POST /v1/scans` + `GET /v1/scans/{id}`.
  Both gates and tenant isolation enforced. ruff clean, mypy clean (48 files), pytest
  204 passed (6 new: end-to-end scan, capability gate, out-of-scope, closed
  engagement, tenant isolation, unsupported track).
