# Phase 7 — Full Spectrum Integration

**Status:** Planned
**Track:** Cross-cutting (depends on all phases)
**Depends on:** Phases 0-6

## Scope

Layer 13: Orchestration. Complete platform integration, CI/CD integration, production hardening.

## Deliverables

1. **Full orchestration (Layer 13)**
   - All 3 tracks running in parallel, findings routing correctly
   - Dependency-aware routing (WRAITH.md §3.1 — 10 conditions)
   - Target-specific tool selection (WRAITH.md §3.2 — 10 target types)
   - Feedback loop: Post-Exploit → Orchestrator
2. **CI/CD integration**
   - GitHub Actions pipeline for automated scanning
   - Pre-commit hooks for agent skill scanning
   - SARIF upload to GitHub Security tab
3. **Production hardening**
   - Results store encryption (WRAITH.md §11.5)
   - Audit log review
   - Performance benchmarks (scan time, engine startup, memory usage)
   - Documentation: user guide, admin guide, API reference
4. **Distribution packaging**
   - License compliance (WRAITH.md §11.6 — SQLMap excluded, Burp excluded)
   - Install script: `curl -fsSL https://wraith.dev/install.sh | sh`
   - Docker image (optional, for CI/CD)

## Acceptance criteria

- [ ] `wraith scan --all` runs all 3 tracks in parallel, produces merged SARIF
- [ ] CI/CD pipeline passes on a reference target
- [ ] Install script works on a clean Ubuntu/macOS machine
- [ ] All 6 known gaps (WRAITH.md §11) resolved or have concrete issue tickets
- [ ] Documentation covers all 13 layers, 3 tracks, 8 phases

## Notes

- This is the "done" phase. Each earlier phase must be independently deliverable; Phase 7 is the polish and integration pass.
- The license matrix (WRAITH.md §11.6) is the hardest constraint here — it determines what can be in a downloadable package.