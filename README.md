# WRAITH — Full-Spectrum Offensive Security + Agentic Security Platform

**Version 2.1** — September 2026

WRAITH is a full-spectrum offensive security architecture that fuses classic penetration testing (recon, web, API, network, cloud, exploitation) with **agentic security** (AI-agent skill scanning, MCP tool poisoning, prompt injection, supply chain). It runs **fully local** with optional LLM augmentation.

## Architecture at a Glance

WRAITH is **not a linear pipeline**. It coordinates **3 parallel analysis tracks** through a central Orchestrator that routes findings by dependency:

```
                     ┌──────────────────────────────────────────┐
                     │            WRAITH ORCHESTRATOR            │
                     └──────┬───────────────┬───────────────┬────┘
                            │               │               │
               ┌────────────▼───┐  ┌────────▼───────┐  ┌───▼────────────┐
               │ Track A        │  │ Track B        │  │ Track C        │
               │ Web & API      │  │ Network & Cloud│  │ SAST & Agentic │
               └────────────┬───┘  └────────┬───────┘  └───┬────────────┘
                            │               │               │
                            └───────┬───────┴───────┬───────┘
                                    ▼               ▼
                            ┌────────────┐  ┌─────────────┐
                            │ Exploitation│→│  Post-Exploit │
                            └────────────┘  └─────────────┘
```

**13 layers:** Recon → Intake → Web Vuln Scan → API Security → Network & AD → Cloud & Infra → SAST → Agentic Security → Exploitation → Post-Exploit → Code Review → Governance → Orchestration

**Primary engines:**
- **[SkillSpector](https://github.com/NVIDIA/SkillSpector)** (Apache-2.0) — agent skill security scanner, 18 pattern categories (MCP tool poisoning, prompt injection, supply chain, behavioral AST, YARA)
- **[Strix](https://github.com/usestrix/strix)** — autonomous AI pentesting agent (multi-agent orchestration)
- **[CubeSandbox](https://github.com/TencentCloud/CubeSandbox)** — hardware-isolated sandbox (KVM/RustVMM, <60ms startup)
- **[Ponytail](https://github.com/DietrichGebert/ponytail)** — code review / minimization plugin
- **ScanAgenticRisk** (self-developed) — rule contract framework, governance model

**External tools:** Metasploit, SQLMap, Burp Suite, Nmap, Shodan

## Repository Layout

```
WRAITH/
├── WRAITH.md              # Full architecture document (reference-grade, v2.1)
├── docs/
│   └── wraith-architecture.html   # Interactive architecture diagram
├── plans/                 # Phase-by-phase implementation plans
│   ├── phase-0-foundation.md
│   ├── phase-1-web-api-track.md
│   ├── phase-2-network-cloud-track.md
│   ├── phase-3-sast-agentic-track.md
│   ├── phase-4-exploitation-engine.md
│   ├── phase-5-post-exploit.md
│   ├── phase-6-governance.md
│   └── phase-7-full-spectrum.md
├── src/
│   ├── cli/               # WRAITH CLI (unified engine interface)
│   └── orchestrator/      # Task routing, scope enforcement
├── config/                # Engine configs, triggers, scope templates
└── README.md
```

## Current Status

- ✅ Architecture reference v2.1 (WRAITH.md) — 3-track non-linear model verified
- ✅ All repo attributions verified against actual git remotes
- ✅ Known gaps documented (Section 11: authorization, blast radius, LLM data boundary, MVP, results-store, licensing)
- 🔲 Phase 0 — Foundation
- 🔲 MVP (Layers 0-1 + 6-7 + SARIF output)

## Known Gaps (must resolve before operational)

1. **Authorization / ROE** — scope allowlist, engagement records, mandatory human gate before exploitation (Layers 8-9)
2. **Autonomy blast radius** — kill-switch, dry-run mode, hard target-scope binding
3. **LLM data boundary** — redaction before external LLM dispatch, opt-in-only
4. **MVP definition** — smallest useful WRAITH
5. **Results-store sensitivity** — encrypted store, access control, audit log
6. **License & packaging** — SQLMap (GPLv2) and Burp (commercial) cannot be bundled

See [WRAITH.md §11](WRAITH.md) for full detail.

## Quick Start (Phase 0)

> Planned. Skeleton only.

```bash
# Clone engines into ./repos/
git clone --depth 1 https://github.com/NVIDIA/SkillSpector.git repos/SkillSpector
git clone --depth 1 https://github.com/usestrix/strix.git repos/strix
```

## Contributing

WRAITH is a collaboration between Ali Moyo (architecture, governance) and contributors. The architecture document is the source of truth; plans in `plans/` are derived from it. Changes to `WRAITH.md` must keep it consistent with the architecture diagram and vice versa.

---

*WRAITH v2.1 — Full-Spectrum Offensive Security Architecture (Non-Linear, 3 Parallel Tracks) — Ali Moyo — September 2026*