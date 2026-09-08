# Phase 1 — Web/API Track (Track A)

**Status:** Planned
**Depends on:** Phase 0
**Runs in parallel with:** Phases 2, 3

## Scope

Layers 0-3: Reconnaissance, Intake, Web Vulnerability Scan, API Security.

## Deliverables

1. **Recon layer (Layer 0)**
   - Passive: Shodan API, certificate transparency, DNS enumeration
   - Active: Nmap port/service detection (with scope allowlist enforcement)
   - Skill integration: `shodan-reconnaissance-and-pentesting`
2. **Intake layer (Layer 1)**
   - Target normalization (URL patterns, CIDR expansion, repo paths)
   - Scope binding: every intake target validated against `Scope`
   - Input hardening per SkillSpector `input_handler.py` caps (100 MiB, 10K zip members)
3. **Web vulnerability scan (Layer 2)**
   - SQLMap integration (external dependency, GPLv2 — do NOT bundle)
   - Burp Suite integration (external, commercial — user-installed only)
   - Deterministic findings first; LLM judgment only for triage
4. **API security (Layer 3)**
   - OWASP API Top 10 checks (2023)
   - AuthN/AuthZ testing, IDOR probes, rate-limit checks
   - OpenAPI schema ingestion for test generation

## Dependencies

- Phase 0 scope/engagement primitives
- External: Shodan API key (optional), Nmap, SQLMap, Burp

## Output feeds

- Orchestrator for Phase 4 (Exploitation) routing
- SARIF findings to results store

## Acceptance criteria

- [ ] All scan targets validated against scope allowlist before probing
- [ ] Deterministic (non-LLM) findings generated first for all web/API categories
- [ ] Findings written to SARIF with severity and confidence
- [ ] No LLM augmentation without explicit `llm.yaml` enablement + redaction

## Notes

- This track is one of the MVP components (WRAITH.md §11.4: Layers 0-1).
- Exploitation of findings belongs to Phase 4 — this phase is detect-only.