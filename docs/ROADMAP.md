# WRAITH Roadmap

A living backlog. Sections are grouped by theme, not strict priority. "Shipped" is
for grounding; everything under "Remaining" is unbuilt unless a box is checked.

Last updated: 2026-09-12.

## Shipped

- Authorization kernel (scope, signed engagements, single-use approval tokens).
- Engine-adapter contract + supervisor; adapters: SkillSpector, Strix, Trivy,
  Semgrep, and the shared SARIF mapper.
- Red Team Annex (methodology generator + authorize/token flow).
- Authority service (multi-tenant: email/password, MFA, API keys, admin), with the
  security-audit findings fixed (MFA-reset takeover, one-time challenges,
  tenant-status enforcement, API-key self-mint, atomic refresh, server logout,
  gated engine run, result-store containment).
- Entitlement layer: Ed25519 CapabilityGrant, role-by-tier matrix, fail-closed
  verifier.
- Runner (server-side execution), all six sub-phases: asymmetric grants, skeleton,
  server-side engagements + durable tokens, defensive scans end-to-end, kill-switch
  (per-tenant + global), and the offensive framework (token-gated + sandbox boundary).
- Login client and end-to-end Runner client (`wraith auth`, `wraith runner`).
- Signed evidence bundles + standalone verifier, and producer integration (a scan
  emits a stored, signed, verifiable bundle).

## Remaining

### 1. Evidence last mile
- [ ] Ship the signed bundle over the one-way signed feed into ThemisIQ (needs the
  ThemisIQ endpoint/contract).

### 2. Differentiators
- [ ] `wraith doctor` + outbound-data preview (readiness checks; preview what a scan
  sends before it runs).
- [ ] Agent BOM.
- [ ] Effective-authority graph.
- [ ] PR-level authority drift.
- [ ] Deterministic replay.
- [ ] Least-privilege recommendations.

### 3. Engine coverage (docs/engine-integration-plan.md)
- [ ] Nmap (recon; closes the `port_scanning` gap, still UNAVAILABLE in the taxonomy).
- [ ] Nuclei (probe).
- [ ] ZAP passive + spider.
- [ ] SQLMap + ZAP active (offensive; unblocked by the exploit track + sandbox).
- [ ] Trivy/Semgrep taxonomy + `redteam_capabilities` routing follow-up.
- [ ] Connect-time scope guard for active tools (via `scope.guard_url()`).

### 4. Authority production hardening (deferred from the security PR)
- [ ] Rate limiting, account lockout, structured audit events.
- [ ] Alembic migrations (replace `create_all`).
- [ ] First-admin bootstrap.
- [ ] MFA lockout recovery (admin-governed MFA reset).

### 5. Deployment / infra (not CI-testable here)
- [ ] Live CubeSandbox on x86_64 Linux + KVM with a pinned image digest.
- [ ] Host the authority and Runner (TLS proxy, PostgreSQL, a durable queue).

### 6. Billing (entitlement phase 5)
- [ ] Subscription lifecycle for Community/Pro/Enterprise + a payment provider
  (needs product decisions).

### 7. Cleanups / governance debt
- [ ] Retire the legacy symmetric `config.entitlement_key` (src/config.py).
- [ ] SBOM + THIRD_PARTY_NOTICES: add the service dependencies (cryptography,
  fastapi, sqlalchemy, uvicorn, argon2-cffi, pyotp, httpx).
- [ ] README currency (still says "fully local" / "skeleton only").
- [ ] CI: pin action SHAs, add a dependency lock.
- [ ] Engine plan: note that `scope.guard_url()` exists.

### 8. Known latent issues (local / file path only; server paths unaffected)
- [ ] Kernel `Engagement` signature omits the mutable `open` field; a closed local
  engagement can be edited open without invalidating the signature. Mitigated
  server-side (the Runner owns `open`).
- [ ] Local file-based approval-token consumption fails open on a corrupt JSON file;
  the Runner's DB-based consumption is unaffected.
- [ ] Red-team methodology/checklist records do not conform to `finding.schema.json`.
