# Phase 2 — Network/Cloud Track (Track B)

**Status:** Planned
**Depends on:** Phase 0
**Runs in parallel with:** Phases 1, 3

## Scope

Layers 4-5: Network & Active Directory, Cloud & Infrastructure.

## Deliverables

1. **Network & AD (Layer 4)**
   - Nmap-driven topology mapping (scope-bounded)
   - SMB/RDP/SSH service enumeration
   - AD attack path mapping (BloodHound-style, read-only collection)
   - Metasploit auxiliary/exploit staging (Phase 4 hook)
2. **Cloud & infrastructure (Layer 5)**
   - Cloud provider config audits (AWS/Azure/GCP — identity-readonly mode)
   - Kubernetes/container posture checks
   - Public-exposure review (Shodan + provider APIs)

## Dependencies

- Phase 0 scope/engagement primitives
- External: Nmap, Metasploit Framework, cloud CLI credentials (read-only)

## Output feeds

- Orchestrator for Phase 4 (Exploitation) routing
- Findings to results store (SARIF)

## Acceptance criteria

- [ ] All network probes bound to scope (no CIDR outside allowlist)
- [ ] Cloud audits use read-only credentials only
- [ ] AD collection is read-only (no password changes, no persistence)
- [ ] Deterministic findings before any LLM triage

## Notes

- Cloud credential handling must follow WRAITH.md §11.5 (results store is as sensitive as the target).
- This track is NOT in the MVP — add after Phase 1 proves the architecture.