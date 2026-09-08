# Phase 6 — Governance & Compliance

**Status:** Planned
**Track:** Cross-cutting (depends on all tracks producing findings)
**Depends on:** Phases 1, 2, 3 (findings pipeline), Phase 0 (results store)

## Scope

Layers 11-12: Code Review, Governance, Compliance.

## Deliverables

1. **Code review engine (Layer 11)**
   - Ponytail integration for human-in-the-loop review
   - Automated code review triggers on findings patterns
   - Review trail linked to Engagement record
2. **Governance & compliance (Layer 12)**
   - ThemisIQ integration layer — GRC platform consuming WRAITH output
   - ISO 27001/42001 control mapping (findings → control gaps)
   - GDPR compliance checks (data discovery, consent, retention)
   - Report generation (executive summary, technical detail, compliance gaps)
3. **Reporting suite**
   - SARIF export (all phases)
   - Executive summary (non-technical, control-gap focused)
   - Technical report (findings with severity, confidence, evidence)
   - Compliance mapping (ISO 27001 Annex A, ISO 42001, GDPR)

## Dependencies

- ThemisIQ integration layer (self-developed)
- Ponytail (MIT, code review)
- SARIF schema for output

## Acceptance criteria

- [ ] Findings from all phases merged into SARIF
- [ ] ISO 27001 Annex A control mapping generated from findings
- [ ] Executive report readable by non-technical stakeholders
- [ ] ThemisIQ feed format documented

## Notes

- This phase is WRAITH's bridge to the GRC world. The CEO/board-facing output lives here.
- ThemisIQ integration is not a hard dependency — WRAITH can produce standalone reports.