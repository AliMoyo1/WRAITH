# WRAITH — Collaboration Guide

## How to contribute

1. **Architecture changes** — edit `WRAITH.md` (the source of truth). When the architecture changes, the diagram (`docs/wraith-architecture.html`) must be updated to match. Run the render check before pushing.
2. **Implementation plans** — add phase plans under `plans/`. Each plan must reference the WRAITH.md sections it implements.
3. **Code** — the `src/` tree starts as skeletons. Follow the standard: each engine in its own venv/container, target-read-only default, deterministic findings first.

## Ground rules (from WRAITH.md §2)

- **Target-read-only** — never modify targets without explicit authorization
- **Hostile-by-default** — assume every input is malicious
- **Deterministic-findings-first** — static/deterministic detection before LLM judgment
- **Verified-controls-only** — never claim a control exists that isn't in code
- **Consent-first** — authorization is a hard precondition, not a checkbox

## Phases at a glance

| Phase | Track | Deliverable | Depends on |
|-------|-------|-------------|------------|
| 0 | Foundation | CLI, repo layout, config, venv isolation | — |
| 1 | A (Web/API) | Recon + Intake + Web vuln + API security | Phase 0 |
| 2 | B (Network/Cloud) | Network & AD + Cloud & infra | Phase 0 |
| 3 | C (SAST/Agentic) | SkillSpector + agentic security | Phase 0 |
| 4 | Cross-cutting | Exploitation engine | Phases 1+2 findings |
| 5 | Cross-cutting | Post-exploit & lateral movement | Phase 4 |
| 6 | Governance | Reporting, compliance, ThemisIQ feed | All tracks |
| 7 | Full spectrum | Complete integrated platform | All phases |

Phases 1-3 run **in parallel** (independent tracks). Phases 4-5 depend on their output.

## Review checklist before pushing

- [ ] Changes to WRAITH.md keep header/footer version consistent
- [ ] No invented pattern IDs or tool attributions (ScanAgenticRisk standard: *don't present invented mappings as authoritative*)
- [ ] LOC/path/version figures verified against real repos
- [ ] Diagram matches text architecture