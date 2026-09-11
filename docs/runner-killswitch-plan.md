# Runner kill-switch plan (server-side execution, phase 4 sub-phase 5)

Branch: `runner-killswitch` off `main`. Implements section 15.5 / section 8:
per-tenant and global kill, enforced at scan intake and in the worker.

Generalizes the CLI's in-process `.killed` flag to a control-plane state, stored in
the Runner DB so it survives restarts and is visible to every worker.

## Model

`KillSwitch(scope PK, engaged_at)` where `scope` is either `"global"` or a tenant
id. A row present means killed for that scope. Engage inserts, reset deletes.
`is_killed(tenant)` is true when the global row exists or the tenant's row exists.

## Authorization

- Per-tenant kill (`POST /v1/kill`): the tenant comes from the grant; gated by
  `control_plane_scan` (an operator can stop their own tenant's scans). A tenant can
  never affect another tenant.
- Global kill (`POST /v1/admin/kill`): a platform-operator emergency stop, gated by a
  platform key (`WRAITH_RUNNER_PLATFORM_KEY`, no default) in the `X-Platform-Key`
  header, constant-time compared. This is out of band from the tenant entitlement so
  one tenant cannot halt the whole platform; it is a stand-in until a real
  cross-tenant platform-operator identity exists.

## Enforcement

- Intake: `POST /v1/scans` refuses with 503 while the tenant is killed (globally or
  per-tenant), before creating a scan row.
- Worker: `run_scan` checks the kill state at the start and marks the scan `killed`
  without running any engine (covers a scan queued before a kill is engaged). Fully
  halting an already-running engine mid-flight is the sandbox-teardown concern of
  sub-phase 6; for defensive in-process scans, intake plus the pre-run check is the
  enforcement here.

## Steps

- [ ] `runner/config.py`: `platform_key()` (`WRAITH_RUNNER_PLATFORM_KEY`, no default).
- [ ] `runner/models.py`: `KillSwitch`.
- [ ] `runner/repository.py`: `engage_kill`, `clear_kill`, `is_killed`.
- [ ] `runner/worker.py`: `run_scan` checks `is_killed` and marks `killed`.
- [ ] `runner/app.py`: `create_app` gains `platform_key`; `POST /v1/kill` (per-tenant),
  `POST /v1/admin/kill` (global, platform key), and the intake 503 in `POST /v1/scans`.
- [ ] Tests: a per-tenant kill blocks that tenant's scans and not another's, and
  reset restores; kill needs `control_plane_scan`; a global kill blocks all tenants
  and needs the platform key; `run_scan` marks a scan `killed` when the state is set.

## Not in scope

Mid-flight teardown of a running engine (sub-phase 6, hardware isolation). Offensive
tracks (sub-phase 6).

## Verification

ruff check src tests, mypy src, pytest -q all green. No push or merge without
explicit approval.

## Change log

- Built all steps on `runner-killswitch`. `KillSwitch` model + repository
  (engage/clear/is_killed), `runner/config.platform_key`, worker pre-run kill check,
  `POST /v1/kill` (per-tenant, control_plane_scan) and `POST /v1/admin/kill` (global,
  X-Platform-Key), and the intake 503. ruff clean, mypy clean (48 files), pytest 210
  passed (6 new: per-tenant block/reset, tenant isolation, capability gate, global
  block, platform-key requirement, worker marks a queued scan killed).
