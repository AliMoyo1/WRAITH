# Phase 3 — SAST/Agentic Track (Track C)

**Status:** Planned
**Depends on:** Phase 0
**Runs in parallel with:** Phases 1, 2

## Scope

Layers 6-7: Static Analysis (SAST), Agentic Security. This is WRAITH's **unique value proposition**.

## Deliverables

1. **SAST layer (Layer 6)**
   - SkillSpector integration: 71 patterns across 17 categories (static analysis, MCP tool poisoning, supply chain, behavioral AST, YARA)
   - Pattern families (authoritative ids live in the SkillSpector README; mirrored in taxonomy/capabilities.yaml):
     - Prompt Injection: P1-P5, P9
     - Anti-Refusal: AR1-AR3
     - Data Exfiltration: E1-E4
     - Privilege Escalation: PE1-PE3
     - Supply Chain: SC1-SC9
     - Excessive Agency: EA1-EA5
     - Output Handling: OH1-OH3
     - MCP: mcp_tool_poisoning, mcp_least_privilege, mcp_rug_pull analyzers
   - Input hardening via `input_handler.py` (100 MiB, 10K zip, O_PATH)
2. **Agentic security layer (Layer 7)**
   - Agent skill scanning for malicious/excessive-capability skills
   - MCP server config auditing
   - Agent BOM generation
   - Behavioral AST + taint-tracking analysis
3. **Code review engine** — Ponytail integration for human-in-the-loop review

## Dependencies

- Phase 0 scope/engagement primitives
- SkillSpector (Apache-2.0, engine)
- Ponytail (MIT, review)
- ScanAgenticRisk spec (self-developed governance model)

## Output feeds

- Orchestrator for Phase 5 (Post-Exploit & Lateral Movement) routing
- Findings to results store (SARIF)

## Acceptance criteria

- [ ] SkillSpector analyzer set runs cleanly in isolated venv
- [ ] Findings reference real pattern IDs (no invented mappings — ScanAgenticRisk standard)
- [ ] Agent BOM generation works for a reference skill pack
- [ ] LLM-augmented analysis requires explicit opt-in + redaction (WRAITH.md §11.3)
- [ ] This track + Phase 1 forms the MVP (WRAITH.md §11.4)

## Notes

- The skill libraries (50+ security skills from Hermes) are loaded as methodology guides and rule templates.
- YARA rules from SkillSpector extend static detection without LLM.