# WRAITH Authority Service (Entitlement Phase 2 Scope)

Status: DRAFT for review. Date: 2026-09-09. Owner: Ali Moyo.

Builds on the phase 1 enforcement core in docs/entitlement-rbac-subscription.md
(`CapabilityGrant`, `capabilities_for`, `require_entitlement`, `entitlement_key`).
This note scopes phase 2 for review before any code is written.

## 1. What phase 2 is

The hosted, multi-tenant WRAITH authority service: the online component that
authenticates a principal, resolves their roles and their tenant tier, and issues
a short-lived, signed `CapabilityGrant` using the phase 1 primitives. It is the
identity provider and the entitlement issuer.

## 2. What phase 2 is NOT

- Not engine execution. Running scans and engines server-side is phase 4. Phase 2
  issues grants; it does not run the kernel or any engine, and it never authorizes
  a target.
- Not billing. Tier is a stored attribute for now; wiring a billing provider to
  set it is phase 5.
- Not the client. The login CLI and UI are phase 3.
- Not tied to ThemisIQ. Separate identity, per the product decision.

## 3. Boundaries and reuse

- Reuses phase 1: `capabilities_for(roles, tier)` computes the grant's capability
  set; `CapabilityGrant.sign` signs it with the server-held `entitlement_key`; the
  grant is the short-lived access artifact clients carry.
- The entitlement key lives ONLY in the service (environment or a secrets
  manager). It is never shipped to a client, and grant signing never leaves the
  service.
- The service is a new package with its own dependencies (web framework, ORM).
  Those dependencies do NOT touch the stdlib-only `orchestrator` and `entitlement`
  packages; they are declared under a service extra.

## 4. Proposed tech stack

| Concern | Proposal | Note |
|---|---|---|
| Web framework | FastAPI + uvicorn | typed, OpenAPI, TestClient, async |
| Storage | PostgreSQL (prod) via SQLAlchemy 2.0; SQLite for tests | WRAITH has no database today; this is scoped to the service only |
| Migrations | Alembic | schema versioning |
| Password hashing | Argon2id (argon2-cffi) | never store plaintext |
| MFA | TOTP (pyotp) | required for Operator and Admin |
| Access artifact | the phase 1 `CapabilityGrant`, short TTL | reuse, do not reinvent |
| Refresh | opaque refresh token, stored hashed, revocable | survives grant expiry |

New dependencies land only in the service extra; the kernel stays standard
library only.

## 5. Data model (multi-tenant)

Every row except `tenant` is tenant-scoped.

- `tenant(id, name, tier, status, created_at)`
- `principal(id, tenant_id, email, password_hash, status, created_at)` with a
  unique constraint on `(tenant_id, email)`
- `principal_role(principal_id, role)` so a principal may hold more than one role
- `mfa_credential(principal_id, type, secret_encrypted, confirmed_at)`
- `api_key(id, tenant_id, principal_id, name, key_hash, created_at, last_used_at, revoked_at)`
- `refresh_token(id, principal_id, token_hash, issued_at, expires_at, revoked_at)`
- `audit_event(id, tenant_id, principal_id, event, detail, ts)`

Isolation invariant: the tenant is derived from the authenticated principal, never
accepted from the client for cross-tenant reads. It is enforced in a single
data-access layer and covered by cross-tenant refusal tests.

## 6. Auth flows

Login:

1. `POST /v1/auth/login {email, password}` verifies the Argon2 hash.
2. If the principal has confirmed MFA (required for Operator and Admin), the
   response is a short-lived MFA challenge, NOT a grant.
3. `POST /v1/auth/mfa/verify {challenge, code}` verifies the TOTP code.
4. On success the service issues a refresh token (opaque, stored hashed) and a
   `CapabilityGrant` for `capabilities_for(roles, tier)`, signed, short TTL.

Refresh:

- `POST /v1/auth/refresh {refresh_token}` re-resolves the principal's roles and
  the tenant tier (so a downgrade or role change takes effect) and issues a fresh
  grant. The refresh token must be valid, unexpired, and not revoked.

API keys (automation and CLI):

- `POST /v1/auth/token` with an API key as bearer issues a grant directly. API
  keys are a strong secret, scoped, and revocable. See open question 5 on whether
  a key may hold elevated (Operator) capability.

Logout and MFA enrollment:

- `POST /v1/auth/logout` revokes the refresh token. Grants are short-lived and
  simply expire (revocation list deferred, per the phase 1 decision).
- `POST /v1/mfa/enroll` returns a TOTP provisioning secret; `POST /v1/mfa/confirm`
  confirms it. An Operator or Admin cannot obtain a grant carrying elevated
  classes until MFA is confirmed.

## 7. API surface (v1)

Public (the only no-grant surface, answering the default-deny question):

- `GET /v1/healthz` liveness

Auth:

- `POST /v1/auth/login`, `POST /v1/auth/mfa/verify`, `POST /v1/auth/refresh`,
  `POST /v1/auth/logout`, `POST /v1/auth/token`

Self-service (valid grant required):

- `GET /v1/me` (principal, roles, tier, granted classes)
- `POST /v1/mfa/enroll`, `POST /v1/mfa/confirm`
- `POST /v1/api-keys`, `GET /v1/api-keys`, `DELETE /v1/api-keys/{id}`

Admin (require the ADMIN capability class, tenant-scoped):

- `POST /v1/admin/principals`, `GET /v1/admin/principals`,
  `PATCH /v1/admin/principals/{id}` (roles, status)
- `PATCH /v1/admin/tenant` (manual tier changes until billing in phase 5)

Every non-public endpoint requires a valid grant as a bearer credential, and admin
endpoints additionally pass through `require_entitlement(..., ADMIN, ...)`.

## 8. Security

- Passwords: Argon2id; never logged or returned.
- MFA secrets: encrypted at rest with a service key (again distinct from the
  entitlement, signing, and result keys).
- API keys and refresh tokens: stored only as hashes; the secret is shown once at
  creation.
- Rate limiting and lockout on login and MFA verification to blunt brute force.
- Audit through the existing redacting logger; auth events and admin actions are
  recorded per tenant.
- TLS terminates at a reverse proxy in front; the app assumes HTTPS.
- The service enforces the entitlement gate for its own admin operations. It does
  not run engines, so there is no target authorization here.

## 9. Testing

- FastAPI TestClient with SQLite (in-memory or a temp file); the database session
  and the entitlement key are dependency-injected.
- Cover: login success and failure, MFA required for Operator and Admin, MFA
  verify, refresh re-resolving roles and tier, API key to grant, that a grant's
  capabilities equal `capabilities_for(roles, tier)`, expired grant rejected,
  admin RBAC (a non-admin is denied), and TENANT ISOLATION (a principal in tenant
  A cannot read or act on tenant B).
- ruff, mypy, and pytest stay green. SQLAlchemy models are typed (the mypy plugin
  or typed mappings) so the type gate holds.

## 10. Deployment (noted, not built here)

Containerized behind a TLS-terminating reverse proxy, with a managed PostgreSQL
instance. Secrets (the entitlement key, the MFA encryption key, the database URL)
come from the environment or a secrets manager, never the repo. Alembic migrations
run on deploy. Deployed separately from ThemisIQ.

## 11. Open questions for phase 2

1. Storage: confirm PostgreSQL (prod) plus SQLite (test) via SQLAlchemy, or a
   different store.
2. Signup model: self-serve tenant signup, or invite and admin-provisioned tenants
   only to start?
3. Access artifact: use the `CapabilityGrant` directly as the bearer credential
   (recommended, reuses phase 1), or wrap it in a separate JWT access token?
4. Email: is transactional email (verification, password reset, invites) in phase
   2, or deferred (admin-driven) to keep phase 2 smaller? Deferring is recommended.
5. API key elevation: may an API key carry Operator (exploit) capability, or are
   keys capped below elevated classes for safety? Capping is the safer default.
6. Grant TTL and refresh-token lifetime values.

## 12. Sub-rollout (phase 2 lands as several green PRs, not one)

1. Service skeleton: the FastAPI app, config (database URL, entitlement key),
   the SQLAlchemy base, Alembic, `GET /v1/healthz`, dependency wiring, and the
   tenant-scoped data-access layer with an isolation test. New dependencies land
   here.
2. Identity and login (no MFA yet): tenants, principals, Argon2 passwords,
   `POST /v1/auth/login` issuing a refresh token and a grant, and `GET /v1/me`.
3. MFA: TOTP enroll, confirm, and verify; enforce MFA for Operator and Admin at
   login.
4. Grant issuance and refresh: harden the `capabilities_for` wiring, make refresh
   re-resolve roles and tier, and make the grant TTL configurable.
5. API keys: create, list, and revoke, plus `POST /v1/auth/token`.
6. Admin endpoints: tenant-scoped principal, role, and tier management, gated by
   the ADMIN capability class.

Recommended: start with sub-phase 1 (skeleton, storage, and the isolation test),
reviewed before sub-phase 2. Each sub-phase is its own PR, green on ruff, mypy,
and pytest.
