# Runner skeleton plan (server-side execution, phase 4 sub-phase 2)

Branch: `runner-skeleton` off `main`. Implements section 15.2 of
docs/server-side-execution-scope.md: the Runner service, tenant-scoped storage,
`GET /v1/healthz`, public-key grant-verification middleware, the capability-class
check, and an isolation test.

Architecture rule (scope note 4.1): the Runner is a separate service that depends
only on the shared `entitlement` library and the grant PUBLIC key. It must not
import from `authority` and must never hold the signing secret.

## Steps

- [x] Move the grant bearer codec (`encode_grant`/`decode_grant`) into the shared
  `entitlement` package (it is the grant wire format, not authority-specific), and
  point the authority at the shared functions. No behaviour change; authority suite
  still green.
- [x] `src/runner/` package: `config` (runner DB url, `WRAITH_ENTITLEMENT_PUBLIC_KEY`
  base64, no default, mirrors the authority's key encoding), `db` (own
  Base/engine/session/create_all, separate from the authority), `models`
  (tenant-scoped `Scan`), `repository` (create/get/list scans, every call bound to
  tenant_id).
- [x] `runner.create_app`: `GET /v1/healthz` (public); `_grant_from_header` decodes
  the bearer, verifies with the public key, and rejects
  missing/malformed/invalid/expired with 401; `_require_class` returns 403 when the
  grant lacks the class; `GET /v1/scans` gated by `control_plane_read` and scoped to
  the grant's tenant. (POST /v1/scans and the worker are sub-phase 4.)
- [x] Tests (tests/test_runner.py): healthz; 401 for no/garbage/expired/wrong-key
  grant; 403 for a valid grant missing the class; tenant isolation, a grant for
  tenant A over `GET /v1/scans` sees only tenant A's scans (seeded via the
  repository), never tenant B's, at both the API and repository level.

## Not in scope (later sub-phases)

Engagement records and token machinery (3), `POST /v1/scans` plus the worker and
per-tenant encrypted results (4), the kill-switch (5), offensive execution (6).

## Verification

ruff check src tests, mypy src, pytest -q all green. No push or merge without
explicit approval.

## Change log

- Built the Runner skeleton + shared-codec move on `runner-skeleton`. ruff clean,
  mypy clean (42 files), pytest 182 passed (7 new Runner tests). The Runner imports
  only `entitlement` (never `authority`) and holds only the public key.
