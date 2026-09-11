# Engine Integrations - Corrected Implementation Plan

Status: DRAFT for review. Date: 2026-09-11. Owner: Ali Moyo.

Supersedes the external draft `engine-integrations-implementation.md`. That draft
had the right direction but several defects: a safety flaw (auto-running
exploitation tools without the token gate), field mappings that violate the
finding schema, CLI wiring that misses the `--track all` path, a
system-binary model that does not fit the loader, config entries that duplicate
existing ones, and pervasive identifier typos. This plan is written against the
verified state of the code so it can be built without re-deriving those facts.

## 1. Purpose and scope

Add dedicated engine adapters so WRAITH covers gaps that the taxonomy records as
unbuilt (starting with `port_scanning`, currently `status: UNAVAILABLE, note:
"adapter not built"` in `taxonomy/capabilities.yaml`). Candidate engines: Trivy,
Semgrep, Nmap, Nuclei, OWASP ZAP, SQLMap.

In scope: the `EngineAdapter` subclasses, their normalization to the finding
schema, their availability checks, CLI selection wiring, and the config/taxonomy
records. Out of scope: bundling any engine (all remain operator-installed external
subprocesses), and any change to the authorization kernel's contract.

Relationship to phase 4 (server-side execution): these adapters are plain
`EngineAdapter` subclasses, so the Runner's future worker (server-side execution
sub-phase 4) reuses them unchanged. Building them now wires them into the local
CLI scan path; they will run server-side later without modification. The offensive
engines especially benefit from the Runner's per-run isolation, which is a reason
to sequence them late (see section 10).

## 2. Ground truth (verified against the code)

Use these real symbols. Do not invent names.

- Adapter contract (`src/adapters/base.py`): abstract methods are
  `is_available(self) -> tuple[bool, str]`, `_default_runner(self, request) ->
  SubprocessResult`, `_normalize(self, raw_output: str) -> list[dict]`; plus
  `engine_version(self) -> str | None`. The concrete `run(self, request, runner=
  None)` wrapper already maps unavailable to `UNAVAILABLE`, timeout to `TIMEOUT`,
  non-zero exit to `ERROR`, and a parse exception to `ERROR`. Adapters do NOT
  re-implement status handling; they implement only the four methods above.
- Test injection: pass a `runner` callable to `.run(request, runner=...)` to feed
  canned output without the engine installed. `command_prefix` (see
  `StrixAdapter.__init__`) makes `is_available` resolve a command in tests; it does
  not by itself short-circuit the `engine_path.exists()` check.
- Secrets: `scrubbed_env()` removes `WRAITH_SIGNING_KEY` and `WRAITH_RESULT_KEY`;
  `run_subprocess(cmd, cwd, timeout, env=None)` scrubs by default.
- Loader (`src/cli/wraith.py` `_build_adapter`): constructs
  `ADAPTERS[name](engine_path, pinned_commit=pin)` where `engine_path =
  _REPO_ROOT / _ENGINE_DIRS.get(name, f"repos/{name}")` and `pin` comes from
  `config/engines.lock.yaml`. Every adapter must accept `engine_path` positionally
  and `pinned_commit` as a keyword.
- Finding schema (`schemas/finding.schema.json`): `additionalProperties: false` at
  the top level and on nested objects. Required: `finding_id, fingerprint, rule_id,
  layer, severity, confidence, evaluation_result`. `evaluation_result` is one of
  `FINDING, NO_FINDING, REVIEW_REQUIRED, NOT_EVALUATED, ERROR`. `location` allows
  only `target, file, start_line, end_line, url` (no `param`). `taxonomy_mappings`
  items allow only `framework, control_id, name, mapping_type`. `evidence` allows
  `snippet, redactions_applied`.
- SARIF reuse (`src/adapters/sarif.py`): `parse_sarif_results(text) ->
  list[SarifResult]`; `SarifResult` fields are `rule_id, level, message, file,
  start_line, end_line, fingerprint, security_severity, tags`.
- Existing SARIF mapping in `src/adapters/strix.py`: module-level `_LAYER_KEYWORDS`
  and `_severity(level, security_severity)`; methods `_layer_for(self, result)`
  (uses `self.default_layer`) and `_map(self, r)` (emits the full field set:
  `rule_lifecycle`, `implementation_capability`, `policy_evidence`, `remediation`,
  `coverage_status`, plus the required fields).
- Tracks (`src/orchestrator/policy.py`): `Track.WEB_API`, `Track.NETWORK_CLOUD`,
  `Track.SAST_AGENTIC`, `Track.EXPLOITATION`, `Track.POST_EXPLOIT`. There is no
  `WEB_AI`. `require_authorization(track, target, token=None)` requires a valid
  single-use approval token only for `EXPLOITATION` and `POST_EXPLOIT`; analysis
  tracks pass on scope plus an open engagement.
- Existing config: `config/redteam_capabilities.yaml` already defines `nmap` and
  `sqlmap` under `tools:` and routes `sqlmap` as `exploit_sqlmap` (layer 8,
  `gated: true`). `config/engines.lock.yaml` already lists `nmap` and `sqlmap`
  under `external_tools:` (not `engines:`). `taxonomy/capabilities.yaml` has
  `supply_chain` assigned to `skillspector` and `exploitation` as layer 8 gated.
- `docs/engine-integration-features.md` does NOT exist; if a feature doc is wanted
  it is a new file, not a status edit.

## 3. Gating model (safety-critical)

Classify every engine by what it does to the target, and gate accordingly. This is
the correction that matters most.

| Engine | Action class | Layer | Auto-run by `scan`? | Track for `engine run` | Extra gate |
|---|---|---|---|---|---|
| Trivy | static, read-only (repo/image) | 6 | yes (`sast`) | SAST_AGENTIC | none |
| Semgrep | static, read-only (repo) | 6 | yes (`sast`) | SAST_AGENTIC | none |
| Nmap | active recon (packets) | 4 | yes (`network`) | NETWORK_CLOUD | connect-time scope |
| Nuclei | active probe (signatures) | 2/4 | yes (`web`,`api`,`network`) | WEB_API | connect-time scope |
| ZAP passive + spider | passive crawl | 2 | yes (`web`,`api`) | WEB_API | crawl bounded to scope |
| ZAP active scan | attack payloads | 8 | NO | EXPLOITATION | single-use token |
| SQLMap | active SQLi exploitation | 8 | NO | EXPLOITATION | single-use token |

Rules:

- Exploitation-class engines (SQLMap, ZAP active) are NOT added to `_TRACK_DOMAINS`,
  so `wraith scan` never auto-selects them. They map to `Track.EXPLOITATION` in
  `_TRACK_FOR_ENGINE`, so `wraith engine run` gates them through
  `require_authorization(EXPLOITATION, target, token)`. Because `cmd_engine` does not
  pass a token today, running an exploitation engine fails closed until `engine run`
  is extended to accept and consume a single-use token (minted by
  `wraith redteam authorize`, the existing flow). That extension is part of the
  SQLMap/ZAP-active phase, not the earlier ones.
- This preserves the bright line: a scan authorizes analysis; exploitation needs the
  engagement plus a single-use, target-bound token. It also matches the existing
  taxonomy, where `sqlmap` is already `exploit_sqlmap`, layer 8, gated.
- Connect-time scope: `_authorize_scan` checks scope once at intake. Active tools can
  expand what they touch (Nmap on a CIDR, Nuclei across hosts, ZAP spidering to new
  links). Decision (section 12): each active adapter is bound to a single in-scope
  host per run to start and rejects multi-host or CIDR targets; a per-connection scope
  guard is a later change. Do not rely on the one-shot intake check alone for the
  network/web tools.

## 4. Finding normalization rules (schema-accurate)

Every adapter's `_normalize` returns dicts that satisfy the schema:

- Always set the 7 required fields. Mirror `strix._map`'s full set so findings are
  consistent across engines: also set `engine`, `title`, `description`,
  `rule_lifecycle` (`ACTIVE`), `implementation_capability` (`IMPLEMENTED`),
  `evaluation_result`, `policy_evidence` (`state: UNKNOWN` when the engine does not
  assess exploitability), `remediation`, `coverage_status` (`INTEGRATED`).
- `additionalProperties: false` means no stray keys. An injected HTTP parameter goes
  in `evidence.snippet` or the query of `location.url`, never `location.param`.
- `taxonomy_mappings` items carry exactly `framework` and `control_id` (plus optional
  `name`, `mapping_type`). CWE ids become `{framework: "cwe", control_id: "CWE-<n>"}`.
- `severity` and `confidence` use the schema enums only. `evaluation_result` is
  `FINDING` for a confirmed detection, `REVIEW_REQUIRED` for a candidate/hotspot.
- `fingerprint` must be stable across runs (drives cross-scan correlation). Derive it
  from tool-stable identity, not run-specific text (for Nmap: port + protocol +
  service; for Nuclei: template-id + matched-at host; for SQLMap: parameter +
  technique).

## 5. WS0: shared SARIF mapping module (prerequisite, its own PR)

Extract the SARIF-to-finding mapping from `strix.py` into a new
`src/adapters/sarif_mapper.py` so Trivy and Semgrep reuse it without importing
`StrixAdapter`.

- Move `_LAYER_KEYWORDS` and `_severity` verbatim.
- Convert `_layer_for` from a method into `layer_for(result: SarifResult,
  default_layer: int) -> int`.
- Provide `to_finding(result: SarifResult, engine: str, default_layer: int) -> dict`
  that reproduces the ENTIRE field set `strix._map` currently emits.
- Refactor `strix.py` to import and delegate to the shared functions; its existing
  tests must stay green with no change to output.
- Gate: `ruff check src tests`, `mypy src`, `pytest -q` all green; strix findings
  byte-identical to before.

## 6. Per-engine specs

Each adapter: `is_available` (real check; `shutil.which` for system binaries, path +
git pin for cloned repos), `_default_runner` (build argv, `run_subprocess`),
`_normalize` (schema-valid findings), `engine_version`. Tests inject a `runner`.

### 6.1 Trivy (SARIF, static)
- Command: `trivy fs --format sarif --severity CRITICAL,HIGH,MEDIUM --scanners
  vuln,secret,misconfig <path>`; `trivy image ...` when the target is an image ref.
- Availability: `shutil.which("trivy")`; version from `trivy --version`.
- Normalization: SARIF via `sarif_mapper`, default layer 6. Hotspot-style results map
  to `evaluation_result: REVIEW_REQUIRED`.

### 6.2 Semgrep (SARIF, static)
- Command: `semgrep scan --sarif --config auto --metrics off <path>`.
- Availability: `shutil.which("semgrep")`; version from `semgrep --version`.
- Normalization: SARIF via `sarif_mapper`, default layer 6. CWE tags in
  `rule.properties.tags` become `taxonomy_mappings` (framework `cwe`).

### 6.3 Nmap (XML, recon)
- Command: `nmap -sV -sC -oX - -T4 <target>`; add `-p-` when
  `request.options.get("full")`. Read XML from stdout (`-oX -`).
- Availability: `shutil.which("nmap")`; version from `nmap --version`.
- XML parsing: `xml.etree.ElementTree` with external entity resolution disabled
  (guard against XML entity attacks). One finding per open port; NSE `vuln-*` script
  hits become per-port findings. Layer 4. `location.target` is the target; port
  detail goes in `title`/`description`/`evidence`, not `location.param`.
- Pitfall: SYN scan and OS detection need root; fall back to connect scan and warn.
  Do not silently escalate privileges.

### 6.4 Nuclei (NDJSON, probe)
- Command: `nuclei -u <target> -jsonl -t cves/ -t misconfigurations/ -t exposures/
  -rl 150` (confirm the current JSON-lines flag name against the installed nuclei
  version; older builds used `-json`). Parse one JSON object per line, tolerating a
  malformed line.
- Availability: `shutil.which("nuclei")`; version from `nuclei -version`.
- Layer by nuclei `type`: http to 2, dns/tcp/ssl to 4. `location.url` from
  `matched-at`. Severity from `info.severity`.

### 6.5 OWASP ZAP (REST API, passive by default)
- Integration: ZAP runs as a Docker container or local process; the adapter talks to
  its REST API over `urllib.request` (stdlib). Availability: probe the API base URL;
  `UNAVAILABLE` if unreachable.
- Default mode is passive spider plus passive scan, bounded to in-scope hosts. Active
  scan is a separate, exploitation-gated path (section 3), not the default.
- Normalization: alerts to findings; `pluginId` to `rule_id`, ZAP risk to severity,
  ZAP confidence to confidence, CWE to `taxonomy_mappings`. URL and any parameter go
  in `location.url` and `evidence`, not `location.param`.

### 6.6 SQLMap (exploitation, token-gated, built last)
- Exploitation-class: not auto-run; `engine run` only, behind the single-use token.
- Command (when authorized): `sqlmap -u <target> --batch --flush-session
  --output-dir=<workdir>` plus detection options; parse the session output for
  injection points. Techniques B/E/U/S/T map to `rule_id` `sqlmap-tech-<code>`,
  severity CRITICAL, confidence HIGH (MEDIUM for time-based).
- Targets must be URLs with parameters; a bare domain yields no injection points.

## 7. CLI wiring (`src/cli/wraith.py`)

- `_TRACK_DOMAINS`: add only the auto-runnable engines:
  `trivy {"sast"}`, `semgrep {"sast"}`, `nmap {"network"}`,
  `nuclei {"web","api","network"}`, `zap {"web","api"}`. Do NOT add `sqlmap` or a
  `zap` active entry (exploitation is not auto-run).
- `_TRACK_FOR_ENGINE`: `trivy`/`semgrep` to `Track.SAST_AGENTIC`, `nmap` to
  `Track.NETWORK_CLOUD`, `nuclei`/`zap` to `Track.WEB_API`, `sqlmap` (and a distinct
  ZAP-active engine name if split out) to `Track.EXPLOITATION`. Use real `Track`
  members only.
- Fix the `--track all` path: `_adapters_for` currently hardcodes skillspector and
  strix by name in the `track == "all"` branch, so new engines would never fire under
  `scan --track all`. Generalize it: tag each engine as static or dynamic and select
  the ones whose kind matches `classify_target` (static engines when the target is a
  `repo_path`, dynamic engines when it is a `url`/`domain`/`cidr`). Exploitation
  engines stay excluded regardless.
- System binaries do not fit the `repos/<name>` + git-commit model. Options: give the
  binary adapters an `is_available` based on `shutil.which` that ignores `engine_path`,
  and record a version string (not a git commit) in the lockfile. `_ENGINE_DIRS` for a
  system binary is cosmetic at best; prefer not to point it at `/usr/bin` (that is
  POSIX-only and `_REPO_ROOT / "/usr/bin"` is surprising). Decide the pin field
  (version string) in section 9.
- `engine run` is already gated (kill-switch, scope, engagement via `_authorize_scan`)
  from the hardening work. Extending it to accept a `--token` for exploitation engines
  is part of the SQLMap/ZAP-active phase.

## 8. Config and taxonomy (reconciled, no duplication)

- `config/engines.lock.yaml`: add `trivy`, `semgrep`, `nuclei`, `zap` under
  `external_tools:` (binaries/images, operator-installed), each with `source`,
  `license`, `bundled: false`, and a `version` pin field (not a git `commit`). Update
  the existing `nmap` and `sqlmap` entries (add an `adapter` note); keep
  `sqlmap.gated: true`. Do NOT put these under `engines:` (that section documents
  `git rev-parse HEAD` pinning for cloned source engines).
- `config/redteam_capabilities.yaml`: `nmap` and `sqlmap` already exist under
  `tools:`; update them, do not add duplicate keys. Add `trivy`, `semgrep`, `nuclei`,
  `zap` under `tools:`. The real routing is the `capabilities:` list; wire the new
  tools into the relevant capability entries (a SAST/supply-chain capability lists
  trivy/semgrep; web/network probe capabilities list nuclei/zap). `sqlmap` stays on
  `exploit_sqlmap` (layer 8, gated).
- `taxonomy/capabilities.yaml`: flip `port_scanning` to `status: INTEGRATED` (engine
  `nmap`) once its adapter lands. For Trivy, do NOT overwrite `supply_chain` (assigned
  to skillspector); add a distinct domain (for example `dependency_vulns` or
  `container_scan`, engine `trivy`) so both engines' coverage is represented. Add
  domains for nuclei and zap coverage as they land. Add the new engines to the
  `engines:` section following the skillspector record shape.

## 9. Tests

Per adapter, following `tests/test_adapters.py`:
- `_normalize` on canned output returns findings with all required fields, and each
  finding validates against `schemas/finding.schema.json` (add a schema-validation
  assertion so `additionalProperties: false` violations are caught).
- Unavailable, timeout, and error paths are exercised through `run(request,
  runner=...)`; the base wrapper produces `UNAVAILABLE`/`TIMEOUT`/`ERROR`.
- Malformed output yields `ERROR` (parse failure), not a crash.
- CLI: the new name appears in `engine list`; `engine run` respects the kill-switch
  and scope gates; an out-of-scope target returns exit 2.
- Adapter-specific: Nmap XML with entity resolution disabled; Nuclei malformed line;
  ZAP multi-step API flow (mock the REST endpoints); SQLMap technique classification
  and refusal without a token.

## 10. Phasing (risk-ordered, one concern per PR)

1. WS0: `sarif_mapper` extraction (pure refactor).
2. Trivy + Semgrep (static, read-only, analysis gate).
3. Nmap (recon; closes the real `port_scanning` gap; connect-time scope care).
4. Nuclei (probe; scope discipline).
5. ZAP passive + spider (bounded to scope).
6. SQLMap and ZAP active: `Track.EXPLOITATION`, `engine run` token gate, not
   auto-run. Deferred until the Runner provides per-run isolation (decision 2).

## 11. Acceptance (per phase)

- `ruff check src tests`, `mypy src`, `pytest -q` green.
- New adapters registered in `ADAPTERS`; `engine list` shows them.
- Every finding validates against the schema (validation asserted in tests).
- `scan --track <t> --dry-run` selects the intended engines, including under
  `--track all`; exploitation engines never appear in a scan selection.
- Config and taxonomy updated without duplicate keys or clobbered domains.

## 12. Decisions (adopted 2026-09-11)

All four adopted as recommended.

1. Exploitation gating: SQLMap and ZAP active-scan are excluded from `scan`
   auto-select and run only via a token-gated `engine run` (`Track.EXPLOITATION` plus
   a single-use approval token). No exploitation engine is ever auto-run.
2. Sequencing (chosen 2026-09-11): build the cheap defensive slice now (WS0 + Trivy
   + Semgrep, phases 1-2) on the local CLI, then resume the Runner rollout
   (server-side execution sub-phases 3-6). The active engines (Nmap, Nuclei, ZAP
   passive; phases 3-5) land around the Runner's execution path; SQLMap and ZAP
   active-scan (phase 6) wait until the Runner's server-side worker can isolate them
   per run. The adapters are reused by the Runner worker unchanged, so the local-CLI
   work is not throwaway.
3. Connect-time scope: each active adapter (Nmap, Nuclei, ZAP) is bound to a single
   in-scope host per run to start, and rejects multi-host or CIDR targets; a
   per-connection scope guard is deferred to a later change.
4. Trivy taxonomy: add a distinct detection domain (`dependency_vulns` or
   `container_scan`, engine `trivy`) rather than reassigning `supply_chain` from
   skillspector.
