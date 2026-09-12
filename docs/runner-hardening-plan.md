# Runner hardening: audit remediation (findings 1-5)

Remediation of five verified findings on `main`, all in the Runner execution path.
Finding 6 (the authority graph) is handled separately on PR #39. Packaging decided
with the user: one PR for findings 1-5; amend #39 for finding 6.

Each finding was reproduced against the code before this plan was written.

## Finding 1 (P1): engine subprocesses inherit Runner secrets

[base.py](../src/adapters/base.py) `scrubbed_env()` uses a two-entry blacklist
(`WRAITH_SIGNING_KEY`, `WRAITH_RESULT_KEY`). Every other secret in the Runner's
environment (`WRAITH_RUNNER_SIGNING_KEY`, `WRAITH_RUNNER_RESULT_KEY`,
`WRAITH_RUNNER_PLATFORM_KEY`, `WRAITH_EVIDENCE_PRIVATE_KEY`, `WRAITH_RUNNER_DB_URL`,
and any future key) is inherited by the scanned engine subprocess.

Fix: replace the blacklist with a minimal, cross-platform environment allowlist. Only
OS-essential variables (PATH, HOME/USERPROFILE, locale, temp dirs, Windows system
vars, CA-bundle vars) pass to the child. Engine configuration is passed via CLI
arguments, not inherited env.

## Finding 2 (P1): client input becomes signed authorization evidence

[app.py](../src/runner/app.py) `POST /v1/engagements` signs a client-supplied
`authorized_by`, is gated by `control_plane_scan` (held by Analyst), and accepts an
arbitrary scope whose repository paths the defensive engines then read directly on the
host. This permits self-approval, approver spoofing, and scanning any host path the
service can read.

Fix (user chose the fullest code-level option: identity + paths + new capability):

- Identity from the grant: `authorized_by` is set to the verified `grant.principal_id`,
  never client input. `authorized_by` is removed from the request body (and from the
  client and CLI).
- New capability class `control_plane_engage` (Operator-only, Community tier) gates
  engagement authoring, separating it from `control_plane_scan` (Analyst can run scans
  under an Operator-authored engagement but cannot author/approve one). Excluded from
  API-key grants so automation cannot self-author authorization.
- Per-tenant workspace containment: repository paths in the engagement's allow-scope,
  and any repo-path scan target, must resolve within `WRAITH_RUNNER_WORKSPACE_ROOT/<tenant_id>`.
  Absolute or `..`-escaping paths are rejected. Full OS-level sandboxing of defensive
  scans remains a deployment step (CubeSandbox), tracked as a follow-up.

## Finding 3 (P1): failed or unavailable coverage reported as completed

[worker.py](../src/runner/worker.py) initializes `status="completed"` and only changes
it on an exception. An unavailable engine yields zero findings and `completed`.

Fix: derive the scan status from the per-engine results and expose per-engine coverage
through the scan API. Status vocabulary: `completed` (all engines OK), `partial` (some
OK, some not), `not_evaluated` (nothing ran or all unavailable), `failed` (none OK, at
least one error/timeout), `error` (worker exception), `killed`. Persist a per-engine
summary (name, version, status, coverage) on the scan row and return it from
`GET /v1/scans/{id}`.

## Finding 4 (P2): valid SARIF results can fail persistence

[sarif_mapper.py](../src/adapters/sarif_mapper.py) builds a fallback finding id
`{engine}-{rule_id}:{file}:{line}` containing `:` and `/`, which
[result_store `_SAFE_ID`](../src/store/result_store.py) rejects. Worse, the raise is
inside the worker try, so one un-fingerprinted result fails the entire scan.

Fix: generate a safe storage id at the producer. Keep the human-readable `fingerprint`
field; set `finding_id` to `{engine}-{fingerprint}` when that already matches the store
id contract, else `{engine}-{sha256(fingerprint)[:32]}`. Deterministic and safe. The
store stays fail-closed (its strict `_SAFE_ID` is a deliberate traversal guard and is
not weakened).

## Finding 5 (P2): outbound preview understates network activity

[wraith.py](../src/cli/wraith.py) `_preview_scan` says a repo scan has no network
egress and sends nothing to third parties. But Semgrep `--config auto` downloads rules
from its registry and Trivy `fs` fetches vulnerability and check databases.

Fix: make the preview egress-accurate. State that the target's contents are not
uploaded, and list which selected engines make third-party network calls (rule and DB
fetches) even for a local scan.

## Files

- src/adapters/base.py: allowlist env.
- src/adapters/sarif_mapper.py: safe finding id.
- src/cli/wraith.py: accurate preview egress.
- src/runner/worker.py, models.py, repository.py, app.py: status derivation + per-engine
  coverage; engagement identity-from-grant; workspace containment.
- src/runner/config.py: `WRAITH_RUNNER_WORKSPACE_ROOT`.
- src/runner/engagements.py: workspace path helpers.
- src/entitlement/policy.py: `control_plane_engage` class + matrix row.
- src/authority/app.py: exclude `control_plane_engage` from API-key grants.
- src/client/runnerclient.py, src/cli/wraith.py: drop `authorized_by`.
- tests: new coverage for each finding; update runner tests for the engage capability.

## Gates

`ruff check src tests --fix`, `mypy src`, `pytest -q` all green before commit.

## Sequencing note

`control_plane_engage` lands here on `main`. When PR #39 (authority graph) is rebased
onto this new main for the finding-6 amendment, its class-to-activity map and tests are
updated to cover the new class.

## Changelog

- Plan written.
- Finding 1: `adapters/base.py` `scrubbed_env()` is now a cross-platform allowlist.
- Finding 4: `adapters/sarif_mapper.py` derives a storage-safe finding id (readable
  when already safe, else a hash of the fingerprint); the store stays fail-closed.
- Finding 5: `cli/wraith.py` outbound preview lists per-engine third-party fetches.
- Finding 3: `runner/worker.py` derives status (`completed`/`partial`/`not_evaluated`/
  `failed`/`error`/`killed`) from per-engine results and records a per-engine summary
  (`runner/models.py`, `runner/repository.py`); `GET /v1/scans/{id}` returns `engines`.
- Finding 2: new Operator-only `control_plane_engage` class (`entitlement/policy.py`),
  excluded from API-key grants (`authority/app.py`); `POST /v1/engagements` gates on it,
  derives `authorized_by` from the verified grant (dropped from the body, client, CLI),
  and rejects scope repo paths outside `WRAITH_RUNNER_WORKSPACE_ROOT/<tenant>`;
  scan intake rejects repo-path targets outside the tenant workspace
  (`runner/config.py`, `runner/engagements.py`, `runner/app.py`).
- Tests added/updated across test_adapters, test_sarif_mapper, test_entitlement,
  test_authority, test_doctor, test_runner, test_runnerclient.
- Gates green: ruff clean, mypy clean (56 files), pytest 272 passed.
