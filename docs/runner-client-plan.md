# Runner client plan (end-to-end CLI over the Runner)

Branch: `runner-client` off `main`. Adds a client and CLI that drive the Runner,
carrying the grant cached by `wraith auth login`, so the whole stack is usable end
to end: login -> grant -> engagement -> scan -> findings.

Mirrors the existing `AuthClient` (authority) and `wraith auth` CLI.

## Steps

- [ ] `src/client/runnerclient.py`: `RunnerClient` over an injectable httpx client,
  carrying the grant as a bearer token: `create_engagement`, `get_engagement`,
  `close_engagement`, `create_scan` (optional approval token), `get_scan`,
  `list_scans`, and `wait_for_scan` (poll until it leaves the queued state).
  `RunnerError` on a non-200.
- [ ] `src/client/__init__.py`: export `RunnerClient`, `RunnerError`.
- [ ] `src/cli/wraith.py`: `wraith runner engage|scan|status|scans`. `_load_grant`
  loads the cached session and refreshes it against the authority if expired;
  `_runner_url` resolves the Runner base URL (`WRAITH_RUNNER_URL`). `engage` reads a
  scope file and serializes it to the engagement spec; `scan` submits a scan (with an
  optional `--token` for a gated track); `status` and `scans` read results.
- [ ] Tests: `RunnerClient` driven against an in-process Runner app, the full loop
  (create engagement, submit scan, fetch findings, list) plus close and error
  surfacing; a CLI smoke test that `runner` refuses cleanly when not logged in.

## Not in scope

A thin GUI (CLI only here). Minting approval tokens (the existing `wraith redteam
authorize` already does that; `runner scan --token` consumes one).

## Verification

ruff check src tests, mypy src, pytest -q all green. No push or merge without
explicit approval.

## Change log

- Built on `runner-client`: `src/client/runnerclient.py` (RunnerClient + RunnerError),
  exported from `client`; `wraith runner engage|scan|status|scans` with `_load_grant`
  (refresh on expiry) and `_runner_url`. ruff clean, mypy clean (50 files), pytest 220
  passed (4 new: the engagement+scan roundtrip with findings, close, error surfacing,
  and the CLI not-logged-in path).
