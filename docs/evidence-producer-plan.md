# Evidence producer integration

Branch: `evidence-producer` off `main`. Wires the evidence bundle library into the
Runner's scan flow, so a completed scan produces a stored, signed, verifiable bundle
retrievable by API and client. Follows the evidence-bundles library PR.

## What was built

- `ResultStore.put_bundle` / `get_bundle`: store a signed bundle per scan, encrypted
  at rest (Fernet) and audited, under `evidence.bundle` (a non-`.enc` name so it is
  never picked up by the `*.enc` findings glob).
- `runner.worker`: the `Sandbox.run` boundary now returns `list[AdapterResult]`
  (uniform with the supervisor), so both the defensive and sandboxed paths yield the
  same per-engine results. `run_scan` takes an optional `EvidenceContext` (signing
  key + engagement and entitlement summaries); after a scan it builds a bundle from
  the engagement, the grant summary, the per-engine results, and the findings, signs
  it, and stores it.
- `evidence.signing_key_optional`: evidence production is optional, enabled only when
  a signing key is configured.
- Runner app: `create_app` gains `evidence_key` (falls back to the optional env key);
  `POST /v1/scans` captures the engagement and entitlement summaries and passes an
  `EvidenceContext` to the worker; `GET /v1/scans/{id}/evidence` returns the signed
  bundle (tenant-scoped, `control_plane_read`).
- Client + CLI: `RunnerClient.get_evidence`; `wraith runner evidence <scan-id>
  [--out <file>]`, which pairs with `wraith evidence verify`.

## Verification

ruff clean, mypy clean (53 files), pytest 235 passed (5 new: the store bundle round
trip and that it is not listed as a finding, and end-to-end a scan produces a bundle
that verifies with the public key, is tenant-isolated, and is fetchable via the
client).

## Not in scope

The one-way signed feed into ThemisIQ (the bundle is now produced and retrievable;
shipping it over the feed is the next step). The CLI scan path does not yet emit a
bundle (the Runner is the primary producer).
