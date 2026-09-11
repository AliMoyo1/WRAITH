# Signed evidence bundles plan

Branch: `evidence-bundles` off `main`. The first evidence-first differentiator: a
portable, signed record of a scan that a consumer (ThemisIQ, an auditor) can verify
independently with a public key alone. Section 11 of
docs/server-side-execution-scope.md.

## The bundle

A self-contained document holding:
- `engagement`: the authorization record summary (id, authorized_by, approval,
  expiry, scope fingerprint).
- `entitlement`: the grant summary (tenant, principal, roles, tier, capabilities),
  or null for a local scan without a grant.
- `engines`: per-engine summaries (name, version, status, coverage) - what ran.
- `findings`: the normalized findings.
- `completeness`: counts and per-status tallies.
- `content_digest`: sha256 over the canonical engines + findings.
- `created_at`, `version`, and an Ed25519 `signature` over the whole payload.

Signed with Ed25519 so a verifier needs only the public key, no shared secret, and
verifies independently of WRAITH. The producer holds `WRAITH_EVIDENCE_PRIVATE_KEY`;
verifiers hold `WRAITH_EVIDENCE_PUBLIC_KEY` (both base64, no default).

## Steps

- [ ] `entitlement`: generic `sign_bytes` / `verify_bytes` (Ed25519 over arbitrary
  bytes), the shared crypto home.
- [ ] `src/evidence/`: `bundle.py` (EvidenceBundle: build, sign, verify, to/from
  dict, content digest, and a standalone `verify_bundle`), `keys.py` (the key env
  readers), `__init__.py`.
- [ ] `src/cli/wraith.py`: `wraith evidence verify <bundle-file>` - the standalone
  verifier, reading the public key from the environment.
- [ ] Tests: build/sign/verify round trip; tamper a finding -> fails; wrong key ->
  fails; to/from dict; the standalone `verify_bundle`; a null entitlement (local
  scan); and the CLI verify (valid -> 0, tampered -> 2, missing key -> 2).

## Not in scope (follow-ons)

Emitting a bundle automatically after a scan (the producer integration in the Runner
and CLI scan paths), and the one-way signed feed into ThemisIQ. `build_bundle` is the
producer primitive those will call.

## Verification

ruff check src tests, mypy src, pytest -q all green. No push or merge without
explicit approval.

## Change log

- Built on `evidence-bundles`: `entitlement.sign_bytes`/`verify_bytes` (generic
  Ed25519); `src/evidence/` (EvidenceBundle build/sign/verify/to-from-dict, the
  standalone `verify_bundle`, and the key env readers); `wraith evidence verify`.
  ruff clean, mypy clean (53 files), pytest 230 passed (10 new: round trip, unsigned,
  wrong key, tamper detection, dict round trip, standalone verify, malformed, null
  entitlement, and the CLI verify valid/tampered/missing-key).
