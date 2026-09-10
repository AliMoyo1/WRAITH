# Authority hardening plan

Branch: `harden-auth-surface` off `main` (9f05295). Independent of PR #22 (Ed25519);
the vulnerabilities here exist on `main` and are orthogonal to the signing algorithm,
so this lands first and #22 rebases on top.

Scope: the confirmed Critical plus every confirmed High from the security audit
of the authentication surface, the engine-run path, and the result store. Rate
limiting, account lockout, audit events, and Alembic migrations are NOT in scope
(they are prototype-maturity items, not release-blocking Highs); they are tracked
as follow-ups.

## Fixes

- [x] F1 (Critical) MFA re-enrollment takeover. `POST /v1/mfa/enroll` authenticated
  on the password alone and replaced an already-confirmed factor. Now requires a
  valid current TOTP code to re-enroll when a confirmed credential exists;
  first-time enrollment stays a password-only bootstrap.
- [x] F2 (High) MFA challenge replay. The login challenge carried no one-time
  state, so one challenge minted multiple sessions. The challenge now carries a
  jti recorded in `consumed_challenge` at verify and rejected on reuse.
- [x] F3 (High) Disabled tenants still authenticated. `Tenant.status` is now
  enforced on login, MFA verify, refresh, token exchange, and /me.
- [x] F4 (High) API-key self-replication. An API-key-derived grant could mint more
  keys that outlived revocation of the parent. Key create and revoke now require
  the `api_key_manage` marker, which only interactive logins carry.
- [x] F5 (High) Refresh rotation race. Rotation now revokes with a conditional
  UPDATE (only where still active) and denies the caller that loses the race.
- [x] F6 (High) No server-side revocation. Added `POST /v1/auth/logout` that
  revokes the presented refresh token; the CLI calls it best-effort before
  clearing the local session.
- [x] F7 (High) `wraith engine run` bypassed every gate. Now at parity with `scan`:
  kill-switch, scope, and open signed engagement are checked before the adapter runs.
- [x] F8 (High) ResultStore containment. `engagement_id` and `finding_id` are now
  validated against a safe pattern (rejected, not stripped) with a resolved-path
  containment assert, so `../x` cannot escape the root and `a/b` cannot collide
  with `ab`.

## Verification

ruff check src tests: clean. mypy src: clean (36 files). pytest -q: 173 passed.
Regression tests added for every fix. No push or merge without explicit approval.

## Follow-ups (out of scope here, tracked)

- Prototype-maturity items from the audit finding 6: rate limiting, account
  lockout, structured audit events, Alembic migrations, first-admin bootstrap.
- MFA lockout recovery: an admin-governed path to clear a principal's MFA for a
  user who has lost their authenticator (pairs with the F1 re-enrollment guard).
- The scope-only execution path (scan and engine run permit a scope pre-flight
  when no engagement is present): a decision on whether to require an engagement.
- Docs and supply-chain: entitlement crypto note (HMAC vs Ed25519, follows PR #22),
  SBOM and THIRD_PARTY_NOTICES for the service dependencies, README currency.

## Change log

- Implemented F1-F8 on `harden-auth-surface`; all gates green at 173 passed.
