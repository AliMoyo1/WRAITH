# Phase 0 — Foundation

**Status:** Planned (skeleton only)
**Track:** Prerequisite for all tracks
**Depends on:** Nothing

## Objectives

Establish the WRAITH workspace: repo layout, CLI entry point, config system, per-engine isolation, and the scope/authorization primitives that all later phases require.

## Deliverables

1. **Repo layout** — as documented in README (docs/, plans/, src/cli, src/orchestrator, config/)
2. **WRAITH CLI** (`src/cli/`) — unified entry point wrapping all engines:
   - `wraith scan <target> --track web|api|network|cloud|sast|agentic`
   - `wraith scope add|list|rm` — target allowlist management
   - `wraith engage start|close` — engagement records
   - `wraith report <engagement>` — output aggregation
3. **Config system** (`config/`) — YAML-based:
   - `engines.yaml` — engine paths, venv/container bindings
   - `triggers.yaml` — task-routing rules (from Agent Runtime prototype)
   - `scope.yaml` — target allowlist template (empty by default)
   - `llm.yaml` — optional LLM provider config (default: disabled/air-gapped)
4. **Per-engine isolation** — each engine in its own venv (Option A pattern from Agent Runtime) or container
5. **Scope & authorization primitives** (from WRAITH.md §11.1):
   - `Scope` object — signed allowlist of CIDRs, domains, URL patterns, repo paths
   - `Engagement` record — per-session authorization with human approval timestamp
   - **Mandatory human gate** before any Layer 8-9 invocation
6. **Results store skeleton** (WRAITH.md §11.5):
   - Per-engagement encrypted directory
   - Access control (owning user/process only)
   - Audit log of reads/exports

## Acceptance criteria

- [ ] `wraith --version` prints v2.1
- [ ] `wraith scope add 10.0.0.0/24` persists and `wraith scope list` shows it
- [ ] Scope check rejects an out-of-scope target before any engine runs
- [ ] Each engine adapter imports lazily (no engine import at CLI startup)
- [ ] Results store created encrypted per engagement
- [ ] Human gate blocks Layer 8+ invocation without an open Engagement record

## Notes

- The Agent Runtime prototype (11 tests green, OpenRouter DeepSeek wired) is the reference for the task router.
- No external LLM call may occur in this phase unless explicitly enabled in `llm.yaml`.