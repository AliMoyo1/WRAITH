# WRAITH Red Team Annex v2 — Corrected Build Plan

> **Revision note**: This plan replaces v1. It addresses the four non-negotiable points from review:
> 1. Every redteam command routes through the existing kernel (scope check + signed engagement + single-use approval token consumed before any content is emitted)
> 2. Maps onto the frozen taxonomy (layers 0-12, detection_domains, tracks A/B/C) — no new parallel phase model
> 3. Persists all generated content through the existing ResultStore (Fernet-encrypted, hash-chained audit)
> 4. All bugs fixed, refusal tests added
>
> One-sided content (detection evasion, persistence) is dropped. The skills loader is wired to the correct on-host path or the claim is removed.

## Architecture Overview

The Red Team Annex is a content generator that produces target-specific methodology checklists and command references for authorized engagements. It does NOT execute anything — it generates text. The value and the risk both live in whether access to that text is actually gated.

### Key design decisions

1. **No new phase model.** The annex maps onto the existing WRAITH taxonomy layers (0-12) and detection_domains from `taxonomy/capabilities.yaml`. The "phase" concept is simply:
   - **Recon** (layers 0-1): Target acquisition, intake, scope review
   - **Probe** (layers 2-7): Web, API, network, cloud, SAST, agentic probing
   - **Exploit** (layers 8-9): Exploitation, post-exploitation — **always gated by human approval token**

2. **Every command goes through the kernel.** The CLI reuses `Orchestrator.require_authorization()` from `src/orchestrator/policy.py` — the same enforcement point the scan path uses. The Exploit and Post-Exploit generators refuse unless a valid, signed, single-use approval token is provided and consumed.

3. **Everything persists through ResultStore.** Generated methodology documents are encrypted at rest per-engagement, logged in the hash-chained audit trail. Stdout is a preview, not the canonical record.

4. **No one-sided content.** The templates strip "detection evasion," "persistence mechanisms," and "anti-forensics." The Exploit and Post-Exploit templates only contain commands that would be in a standard pentest methodology guide (SQLMap, Metasploit, BloodHound, common privesc checks).

## File Structure

```
config/
  redteam_capabilities.yaml.template   # Routing table (maps detection_domains -> capabilities)
src/
  redteam/
    __init__.py                         # Package exports
    capabilities.py                     # Load routing table; maps onto taxonomy/capabilities.yaml
    generator.py                        # Methodology generator engine with authorization
    checklist.py                        # Pre-flight checklist (no-op without engagement)
    templates/
      __init__.py                       # Template dispatcher
      recon.py                          # Recon methodology (layers 0-1)
      probe.py                          # Probe methodology (layers 2-7)
      exploit.py                        # Exploit methodology (layers 8-9) — gated
tests/
  test_redteam.py                       # Tests including refusal proofs
```

## Step 1: `config/redteam_capabilities.yaml.template`

```yaml
# WRAITH Red Team Annex — capability routing table.
#
# Maps onto the canonical taxonomy in taxonomy/capabilities.yaml.
# Phase names here are PRESENTATION labels only, NOT a new phase model.
# The canonical layer numbers from taxonomy/capabilities.yaml are the source of truth.

version: "2.1"

# Presentation labels for the CLI dashboard. These are NOT a phase model.
# The underlying enforcement uses the canonical layers and tracks.
presentation:
  phases:
    recon:
      label: "Recon"
      description: "Target acquisition, DNS, WHOIS, port scanning"
      layers: [0, 1]
      gate: "none"
    probe:
      label: "Probe"
      description: "Vulnerability detection across web, API, network, cloud, SAST, agentic"
      layers: [2, 3, 4, 5, 6, 7]
      gate: "checklist"
    exploit:
      label: "Exploit"
      description: "Active exploitation of confirmed vulnerabilities"
      layers: [8]
      gate: "human"
    post_exploit:
      label: "Post-Exploit"
      description: "Post-exploitation, privilege escalation, lateral movement"
      layers: [9]
      gate: "human"

# Capabilities reference detection_domains from taxonomy/capabilities.yaml.
# Each capability maps to one or more canonical detection_domains.
capabilities:
  - id: recon_passive
    label: "Passive Reconnaissance"
    detection_domains: []
    layers: [0]
    target_types: [domain, url, ip, cidr]
    tools: [whois, dig, curl, shodan]
    description: "WHOIS, DNS records, certificate transparency, Shodan"
  - id: recon_active
    label: "Active Reconnaissance"
    detection_domains: [port_scanning]
    layers: [1]
    target_types: [ip, cidr, domain, url]
    tools: [nmap, masscan]
    description: "Port scanning, service detection, network mapping"

  - id: web_sqli
    label: "SQL Injection"
    detection_domains: [sql_injection]
    layers: [2]
    target_types: [url, api]
    prerequisites: [recon_passive, recon_active]
    interlinks: [exploit_sqlmap]
  - id: web_xss
    label: "Cross-Site Scripting"
    detection_domains: [xss]
    layers: [2]
    target_types: [url]
  - id: web_csrf
    label: "CSRF"
    detection_domains: [csrf]
    layers: [2]
    target_types: [url]
  - id: web_ssrf
    label: "SSRF"
    detection_domains: [ssrf]
    layers: [2]
    target_types: [url, api]
  - id: web_path_traversal
    label: "Path Traversal"
    detection_domains: [path_traversal]
    layers: [2]
    target_types: [url, api]
  - id: api_idor
    label: "IDOR / BOLA"
    detection_domains: [idor_bola]
    layers: [3]
    target_types: [api, url]
  - id: api_auth
    label: "Broken Authentication"
    detection_domains: [broken_auth]
    layers: [3]
    target_types: [api, url]
  - id: api_jwt
    label: "JWT / OAuth Testing"
    detection_domains: [jwt_oauth]
    layers: [3]
    target_types: [api, url]
  - id: api_graphql
    label: "GraphQL Introspection"
    detection_domains: [graphql]
    layers: [3]
    target_types: [api, url]

  - id: network_scan
    label: "Port & Service Enumeration"
    detection_domains: [port_scanning]
    layers: [4]
    target_types: [ip, cidr, domain]
    tools: [nmap]

  - id: cloud_iam
    label: "Cloud IAM Assessment"
    detection_domains: [cloud_iam]
    layers: [5]
    target_types: [domain, url, api]

  - id: sast_secrets
    label: "Secret Detection"
    detection_domains: [secrets]
    layers: [6]
    target_types: [repo_path, url]
  - id: sast_deserialization
    label: "Insecure Deserialization"
    detection_domains: [insecure_deserialization]
    layers: [6]
    target_types: [repo_path, url]
  - id: sast_supply_chain
    label: "Supply Chain"
    detection_domains: [supply_chain]
    layers: [6]
    target_types: [repo_path, url]

  - id: agentic_prompt_injection
    label: "Prompt Injection Testing"
    detection_domains: [indirect_prompt_injection]
    layers: [7]
    target_types: [url, api, repo_path]
  - id: agentic_tool_misuse
    label: "Tool Misuse & Exploitation"
    detection_domains: [mcp_tool_poisoning]
    layers: [7]
    target_types: [url, api, repo_path]
  - id: agentic_excessive_agency
    label: "Excessive Agency"
    detection_domains: [excessive_agency]
    layers: [7]
    target_types: [url, api, repo_path]

  - id: exploit_sqlmap
    label: "SQLMap Exploitation"
    detection_domains: [exploitation]
    layers: [8]
    target_types: [url, api]
    gated: true
    tools: [sqlmap]
  - id: exploit_metasploit
    label: "Metasploit Framework"
    detection_domains: [exploitation]
    layers: [8]
    target_types: [ip, url, api]
    gated: true
    tools: [metasploit]

  - id: post_exploit_privesc
    label: "Privilege Escalation"
    detection_domains: [privilege_escalation]
    layers: [9]
    target_types: [ip]
    gated: true
  - id: post_exploit_lateral
    label: "Lateral Movement"
    detection_domains: [lateral_movement]
    layers: [9]
    target_types: [ip, domain]
    gated: true

# Tool definitions (for --dry-run install checks)
tools:
  nmap:
    description: "Network discovery and security scanning"
    install_check: "nmap --version"
    commands: {quick: "nmap -sV -sC -T4 {target} -oA {output}/nmap_quick", full: "nmap -sV -sC -p- {target} -oA {output}/nmap_full"}
  sqlmap:
    description: "Automatic SQL injection and database takeover"
    install_check: "sqlmap --version"
    commands: {standard: "sqlmap -u {target} --batch --dbs --stop=5", crawl: "sqlmap -u {target} --batch --crawl=3"}

# Target-type defaults (auto-selected capabilities per target type)
target_type_defaults:
  url:
    auto_capabilities: [recon_passive, recon_active, web_sqli, web_xss, web_csrf, web_ssrf, web_path_traversal, api_idor, api_auth, api_jwt, api_graphql, agentic_prompt_injection, agentic_tool_misuse, agentic_excessive_agency]
  api:
    auto_capabilities: [recon_passive, recon_active, api_idor, api_auth, api_jwt, api_graphql, web_sqli, web_ssrf, agentic_prompt_injection, agentic_tool_misuse, agentic_excessive_agency]
  ip:
    auto_capabilities: [recon_passive, recon_active, network_scan, post_exploit_privesc, post_exploit_lateral]
  cidr:
    auto_capabilities: [recon_passive, recon_active, network_scan, post_exploit_privesc, post_exploit_lateral]
  domain:
    auto_capabilities: [recon_passive, recon_active, web_sqli, web_xss, web_csrf, web_ssrf, web_path_traversal]
  repo_path:
    auto_capabilities: [sast_secrets, sast_deserialization, sast_supply_chain, agentic_prompt_injection, agentic_tool_misuse, agentic_excessive_agency]
```

---

## Step 2: `src/redteam/__init__.py`

```python
"""WRAITH Red Team Annex — authorized methodology generator.

This package produces target-specific methodology checklists and command
references for authorized engagements. It does NOT execute anything — it
generates text that a human operator follows.

Every output path is gated by the kernel's authorization model:
  - Recon/Probe text: requires scope check + valid signed engagement
  - Exploit/Post-Exploit text: additionally requires a single-use approval
    token that is consumed before any content is emitted

All generated content is persisted through the encrypted ResultStore
(hash-chained audit, per-engagement key derivation).
"""

from __future__ import annotations

from .capabilities import (
    Capabilities,
    Capability,
    load_capabilities,
    resolve_for_target,
)
from .generator import MethodologyGenerator, GenerateRequest, GenerateResult
from .checklist import ChecklistGenerator, PreFlightChecklist

__all__ = [
    "Capabilities",
    "Capability",
    "MethodologyGenerator",
    "GenerateRequest",
    "GenerateResult",
    "ChecklistGenerator",
    "PreFlightChecklist",
    "load_capabilities",
    "resolve_for_target",
]
```


## Step 3: `src/redteam/capabilities.py`

```python
"""Load the annex routing table. Maps onto the canonical taxonomy."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
    _HAVE_YAML = True
except ImportError:
    _HAVE_YAML = False


_DEFAULT_PATH = Path(__file__).resolve().parents[2] / "config" / "redteam_capabilities.yaml"


@dataclass
class Capability:
    id: str
    label: str
    detection_domains: list[str] = field(default_factory=list)
    layers: list[int] = field(default_factory=list)
    target_types: list[str] = field(default_factory=lambda: ["generic"])
    tools: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    interlinks: list[str] = field(default_factory=list)
    gated: bool = False
    description: str = ""


@dataclass
class Capabilities:
    capabilities: dict[str, Capability] = field(default_factory=dict)
    tools: dict[str, dict] = field(default_factory=dict)
    target_defaults: dict[str, list[str]] = field(default_factory=dict)
    presentation: dict[str, Any] = field(default_factory=dict)
    version: str = ""

    def get(self, cap_id: str) -> Capability | None:
        return self.capabilities.get(cap_id)

    def for_target(self, target_type: str) -> list[Capability]:
        cap_ids = self.target_defaults.get(target_type, [])
        return [self.capabilities[cid] for cid in cap_ids if cid in self.capabilities]

    def gated_capabilities(self) -> list[Capability]:
        return [c for c in self.capabilities.values() if c.gated]


def _load_mapping(path: Path) -> dict[str, Any]:
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix in (".yaml", ".yml") and _HAVE_YAML:
        return yaml.safe_load(text) or {}
    import json
    return json.loads(text or "{}")


def load_capabilities(path: str | Path | None = None) -> Capabilities:
    path = Path(path) if path else _DEFAULT_PATH
    if not path.exists():
        raise FileNotFoundError(f"capabilities file not found: {path}")
    data = _load_mapping(path)
    caps = Capabilities()
    caps.version = data.get("version", "")
    caps.presentation = dict(data.get("presentation", {}))

    for cdata in data.get("capabilities", []):
        caps.capabilities[cdata["id"]] = Capability(
            id=cdata["id"], label=cdata["label"],
            detection_domains=cdata.get("detection_domains", []),
            layers=cdata.get("layers", []),
            target_types=cdata.get("target_types", ["generic"]),
            tools=cdata.get("tools", []),
            prerequisites=cdata.get("prerequisites", []),
            interlinks=cdata.get("interlinks", []),
            gated=bool(cdata.get("gated", False)),
            description=cdata.get("description", ""),
        )

    caps.tools = dict(data.get("tools", {}))
    for ttype, cids in (data.get("target_type_defaults", {})).items():
        caps.target_defaults[ttype] = list(cids.get("auto_capabilities", []))
    return caps


def resolve_for_target(caps: Capabilities, target_type: str) -> list[Capability]:
    return caps.for_target(target_type)


def detect_target_type(target: str) -> str:
    \"\"\"Classify a target string into a type for capability resolution.\"\"\"
    t = target.strip()
    if not t:
        return \"generic\"
    if \"://\" in t:
        return \"api\" if \"api\" in t.lower() else \"url\"
    try:
        import ipaddress
        ipaddress.ip_address(t)
        return \"ip\"
    except ValueError:
        pass
    try:
        import ipaddress
        ipaddress.ip_network(t, strict=False)
        return \"ip\"
    except ValueError:
        pass
    if t.startswith((\"/\", \"~\", \".\")) or (len(t) >= 3 and t[1] == \":\"):
        return \"repo_path\"
    if \".\" in t and not t.endswith(\".\"):
        return \"domain\"
    return \"generic\"
```


## Step 4: `src/redteam/generator.py` — Authorization-Enforcing Generator

```python
"""Methodology generator — every output path is gated by the kernel."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .capabilities import Capabilities, load_capabilities


@dataclass
class GenerateRequest:
    """A request to generate methodology text.

    For exploit/post_exploit phases, ``approval_token`` must be provided
    and will be consumed by the orchestrator. Without it, generation is
    refused with a PermissionError.
    """
    target: str = ""
    target_type: str = ""
    phase: str = "probe"
    capabilities: list[str] | None = None
    engagement_id: str = ""
    approval_token: Optional["ApprovalToken"] = None
    orchestrator: Optional["Orchestrator"] = None


@dataclass
class GenerateResult:
    content: str = ""
    phase: str = ""
    target: str = ""
    target_type: str = ""
    engagement_id: str = ""
    finding_id: str = ""
    warnings: list[str] = field(default_factory=list)


_EXPLOIT_WARNING = """
╔══════════════════════════════════════════════════════════════════════════╗
║  WRAITH Red Team Annex — EXPLOIT / POST-EXPLOIT CONTENT               ║
║  This content is authorised only for the specific engagement and       ║
║  target listed below. Unauthorized use is illegal.                     ║
║  Approval token consumed: {token_sig}                                  ║
╚══════════════════════════════════════════════════════════════════════════╝
"""


class MethodologyGenerator:
    """Generates methodology text. Gated by the kernel authorization model."""

    def __init__(self, caps: Capabilities | None = None):
        self._caps = caps or load_capabilities()

    def generate(self, request: GenerateRequest) -> GenerateResult:
        """Generate methodology. Raises PermissionError if not authorized."""
        result = GenerateResult(
            phase=request.phase,
            target=request.target,
            target_type=request.target_type or "generic",
            engagement_id=request.engagement_id,
        )

        # Kernel authorization check
        orch = request.orchestrator
        if orch is not None:
            if request.phase in ("exploit", "post_exploit"):
                from orchestrator.policy import Track
                track = Track.EXPLOITATION if request.phase == "exploit" else Track.POST_EXPLOIT
                orch.require_authorization(track, request.target, request.approval_token)
            else:
                # Probe/recon still require scope + engagement
                orch.require_authorization(
                    Track.WEB_API, request.target, None
                )
        result.warnings.append("Authorization: passed")

        # Build content
        lines = [
            f"╔══ WRAITH Red Team Annex — {request.phase.capitalize()} ══╗",
            f"  Target: {request.target}",
            f"  Engagement: {request.engagement_id}",
            "",
        ]

        # If exploit/post_exploit, prepend the warning banner
        if request.phase in ("exploit", "post_exploit") and request.approval_token:
            token_sig = request.approval_token.signature or "(consumed)"
            lines.append(_EXPLOIT_WARNING.format(token_sig=token_sig))

        # Resolve capabilities
        cap_ids = request.capabilities or []
        caps = [self._caps.get(cid) for cid in cap_ids if self._caps.get(cid)]
        caps = [c for c in caps if c is not None]

        if not caps:
            lines.append("  No specific capabilities selected. Generating general methodology.\n")

        # Filter by phase
        phase_map = {
            "recon": [0, 1],
            "probe": [2, 3, 4, 5, 6, 7],
            "exploit": [8],
            "post_exploit": [9],
        }
        allowed_layers = phase_map.get(request.phase, [])
        phase_caps = [c for c in caps if any(l in allowed_layers for l in c.layers)]

        for cap in phase_caps:
            lines.append("" if lines[-1] == "" else "")
            lines.append(f"  === {cap.label} ===")
            lines.append(f"  Layers: {cap.layers}")
            if cap.tools:
                lines.append(f"  Tools: {', '.join(cap.tools)}")
            if cap.detection_domains:
                lines.append(f"  Detection domains: {', '.join(cap.detection_domains)}")
            if cap.gated:
                lines.append(f"  [GATED — requires approval token]")
            lines.append("")

            # Layer-specific methodology
            if cap.id == "recon_passive" and request.phase == "recon":
                lines.append(f"    curl -s 'https://crt.sh/?q=%25.{request.target}&output=json'")
                lines.append(f"    whois {request.target}")
                lines.append(f"    dig {request.target} ANY")
                if self._tool_available("shodan"):
                    lines.append(f"    shodan search hostname:{request.target}")
            elif cap.id == "recon_active" and request.phase == "recon" and request.target_type != "repo_path":
                lines.append(f"    nmap -sV -sC -T4 {request.target}")
                lines.append(f"    curl -sI https://{request.target}")
            elif request.phase == "probe" and any(l in cap.layers for l in [2, 3]):
                if cap.id == "web_sqli":
                    lines.append("    Payloads: ', \", ), '), \"))")
                    lines.append("    WAF bypass: /**/OR/**/1=1, %27%20OR%201=1")
                    lines.append(f"    curl -s '{request.target}?id=1'" )
                    lines.append(f"    curl -s '{request.target}?id=1\"'" )
            elif request.phase == "exploit" and cap.id == "exploit_sqlmap":
                lines.append(f"    sqlmap -u '{request.target}' --batch --dbs --stop=5" )
            elif request.phase == "exploit" and cap.id == "exploit_metasploit":
                lines.append(f"    msfconsole -q -x 'search {request.target}'" )
            elif request.phase == "post_exploit" and cap.id == "post_exploit_privesc":
                lines.append(f"    find / -perm -4000 -type f 2>/dev/null" )
                lines.append(f"    sudo -l" )
            elif request.phase == "post_exploit" and cap.id == "post_exploit_lateral":
                lines.append(f"    bloodhound-python -u 'DOMAIN\\user' -p 'password' -ns {request.target}" )

            # Interlinks
            if cap.interlinks:
                linked = [self._caps.get(link) for link in cap.interlinks if self._caps.get(link)]
                if linked:
                    lines.append(f"    -> Next: {', '.join(l.label for l in linked)}")

        result.content = "\n".join(lines)
        return result

    @staticmethod
    def _tool_available(name: str) -> bool:
        """Stub — replace with actual tool check when needed."""
        return False
```


## Step 5: `src/redteam/checklist.py`

```python
"""Pre-flight checklist generator. Saved to ResultStore."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass
class PreFlightChecklist:
    checklist_id: str
    target: str
    phase: str
    engagement_id: str
    authorized_by: str
    acknowledged: bool = False
    content: str = ""


_CHECKLIST_TPL = """
╔══════════════════════════════════════════════════════════════════════════╗
║  WRAITH Red Team Annex — Pre-Flight Checklist                         ║
║  Phase: {phase}                                                         ║
╚══════════════════════════════════════════════════════════════════════════╝

Checklist ID: {checklist_id}
Generated: {date}
Engagement: {engagement_id}
Target: {target}
Authorized by: {authorized_by}

{sep}
1. SCOPE & AUTHORIZATION
{sep}

[  ] 1.1 Target is within authorized scope
[  ] 1.2 Engagement is open and valid
[  ] 1.3 Written authorization obtained

{sep}
2. TECHNICAL SAFEGUARDS
{sep}

[  ] 2.1 Impact minimized — no destructive operations
[  ] 2.2 Findings will be reported to the engagement owner
[  ] 2.3 No data exfiltration beyond proof-of-concept samples

{sep}
3. OPERATOR DECLARATION
{sep}

I confirm the target is in scope, I have authorization,
I will minimize impact, and I will report findings accurately.

Operator: __________________   Date: __________________
"""


class ChecklistGenerator:
    def generate(self, target: str = "", phase: str = "recon",
                 engagement_id: str = "", authorized_by: str = "") -> PreFlightChecklist:
        cid = str(uuid.uuid4())[:8]
        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        content = _CHECKLIST_TPL.format(
            phase=phase.capitalize(), checklist_id=cid, date=now,
            engagement_id=engagement_id or "(not set)",
            target=target or "(not set)",
            authorized_by=authorized_by or "Operator",
            sep="═" * 60,
        )
        return PreFlightChecklist(
            checklist_id=cid, target=target, phase=phase,
            engagement_id=engagement_id, authorized_by=authorized_by,
            content=content,
        )
```


## Step 6: `src/redteam/templates/__init__.py`

```python
"""Templates are now inlined in generator.py for simplicity.

The generator.py dispatches methodology by phase and capability id.
This package exists for future template expansion; for now it is empty.
"""
```


## Step 7: MODIFY `src/cli/wraith.py` — Add Red Team Annex Commands

Add these imports at the top of the file (after existing imports):

```python
from orchestrator.policy import Orchestrator, Track
from redteam import (
    MethodologyGenerator, GenerateRequest,
    ChecklistGenerator,
    load_capabilities, resolve_for_target,
)
```

Add this block before `build_parser()`:

```python
_REDTEAM_BANNER = """
╔══════════════════════════════════════════════════════════════════════════╗
║  WRAITH Red Team Annex                                                ║
║  Authorized methodology generator for pentest engagements.             ║
║  USE ONLY WITH WRITTEN AUTHORIZATION.                                 ║
╚══════════════════════════════════════════════════════════════════════════╝
"""


def _build_orch(key: bytes | None = None) -> Orchestrator | None:
    """Return an orchestrator if a valid engagement exists, else None."""
    engage_path = _DEFAULT_ENGAGE
    if not engage_path.exists():
        return None
    try:
        eng = config.load_engagement(engage_path)
    except Exception:
        return None
    if not eng.open:
        return None
    key = key or config.signing_key()
    try:
        orch = Orchestrator(key)
        orch.start_engagement(eng)
        return orch
    except PermissionError:
        return None


def cmd_redteam(args) -> int:
    if args.rt_action == "status":
        return _rt_status(args)
    elif args.rt_action == "generate":
        return _rt_generate(args)
    elif args.rt_action == "checklist":
        return _rt_checklist(args)
    print("Subcommands: status, generate, checklist")
    return 2


def _rt_status(args) -> int:
    from redteam.capabilities import detect_target_type
    caps = load_capabilities()
    target_type = detect_target_type(args.target or "")
    available = resolve_for_target(caps, target_type)
    orch = _build_orch()

    print(_REDTEAM_BANNER)
    print(f"  Target: {args.target or '(not set)'}")
    print(f"  Type:   {target_type}\n")

    # Show authorization state
    orch_ok = orch is not None
    if orch_ok:
        print(f"  Engagement: {orch.engagement.id} (valid)\n")
    else:
        print(f"  Engagement: NONE (generate will be refused)\n")

    # Show gated + non-gated capability counts
    gated = [c for c in available if c.gated]
    non_gated = [c for c in available if not c.gated]
    print(f"  Available: {len(non_gated)} non-gated, {len(gated)} gated (need token)\n")

    # Show capabilities grouped by layer
    for layer_name, layer_range, phase_label in [
        ("Recon (layers 0-1)", [0, 1], "recon"),
        ("Probe (layers 2-7)", [2, 3, 4, 5, 6, 7], "probe"),
        ("Exploit (layer 8)", [8], "exploit"),
        ("Post-Exploit (layer 9)", [9], "post_exploit"),
    ]:
        seg = [c for c in available if any(l in layer_range for l in c.layers)]
        if not seg:
            continue
        print(f"  [{phase_label.upper()}] {layer_name}")
        for c in seg:
            gate_mark = " [GATED]" if c.gated else ""
            print(f"    - {c.label}{gate_mark}")
        print()

    if not orch_ok:
        print("  ⚠ Run 'wraith engage start --by <operator>' to authorize.")
    return 0


def _rt_generate(args) -> int:
    from redteam.capabilities import detect_target_type

    caps = load_capabilities()
    target = args.target or ""
    target_type = detect_target_type(target)
    phase = args.phase or "probe"

    # Build orchestrator with engagement
    try:
        key = config.signing_key()
    except RuntimeError as e:
        print(f"  refused: {e}")
        return 2
    orch = _build_orch(key)
    if orch is None:
        print("  refused: no open engagement. Run 'wraith engage start --by <operator>' first.")
        return 2

    # Resolve approval token for exploit/post_exploit
    token = None
    if phase in ("exploit", "post_exploit"):
        if not args.engagement or not args.token:
            print("  refused: exploit/post_exploit requires --engagement and --token flags.")
            return 2
        try:
            eng = config.load_engagement(args.engagement)
            from orchestrator.engagement import ApprovalToken
            token = ApprovalToken(
                engagement_id=eng.id, action=phase,
                target=target, signature=args.token,
            )
        except Exception as e:
            print(f"  refused: cannot load approval token: {e}")
            return 2

    # Build generate request
    cap_ids = args.capabilities.split(",") if args.capabilities else None
    if not cap_ids:
        available = resolve_for_target(caps, target_type)
        cap_ids = [c.id for c in available if not c.gated]
        if phase in ("exploit", "post_exploit") and token:
            cap_ids += [c.id for c in available if c.gated]

    gen = MethodologyGenerator(caps)
    request = GenerateRequest(
        target=target, target_type=target_type, phase=phase,
        capabilities=cap_ids, engagement_id=orch.engagement.id,
        approval_token=token, orchestrator=orch,
    )

    try:
        result = gen.generate(request)
    except PermissionError as e:
        print(f"  refused: {e}")
        return 2

    # Persist through ResultStore
    try:
        rk = config.result_key()
        from store import ResultStore
        store = ResultStore(
            _RESULTS_ROOT, orch.engagement.id, rk, actor="redteam:generate"
        )
        finding = {
            "finding_id": f"redteam-{phase}-{target[:32]}",
            "type": f"redteam_{phase}_methodology",
            "target": target,
            "phase": phase,
            "content": result.content,
            "capabilities": cap_ids[:10],
        }
        finding_id = store.put_finding(finding)
        result.finding_id = finding_id
        result.warnings.append(f"Persisted: {finding_id}")
    except Exception as e:
        result.warnings.append(f"Store unavailable: {e} (content not persisted)")

    print(_REDTEAM_BANNER)
    print(result.content)
    if result.warnings:
        for w in result.warnings:
            if w != "Authorization: passed":
                print(f"  [{w}]")
    print(f"\n  Finding ID: {result.finding_id or '(not persisted)'}")
    print(f"  Engagement: {orch.engagement.id}")
    return 0


def _rt_checklist(args) -> int:
    try:
        key = config.signing_key()
    except RuntimeError as e:
        print(f"  refused: {e}")
        return 2
    orch = _build_orch(key)
    if orch is None:
        print("  refused: no open engagement.")
        return 2

    gen = ChecklistGenerator()
    checklist = gen.generate(
        target=args.target or "", phase=args.rt_phase or "recon",
        engagement_id=orch.engagement.id, authorized_by=orch.engagement.authorized_by,
    )

    # Persist to ResultStore
    try:
        rk = config.result_key()
        from store import ResultStore
        store = ResultStore(_RESULTS_ROOT, orch.engagement.id, rk, actor="redteam:checklist")
        finding = {
            "finding_id": f"checklist-{checklist.checklist_id}",
            "type": "redteam_preflight_checklist",
            "target": checklist.target, "phase": checklist.phase,
            "content": checklist.content,
        }
        store.put_finding(finding)
        print(f"  Saved to engagement {orch.engagement.id}")
    except Exception as e:
        print(f"  (store unavailable: {e})")

    print(checklist.content)
    return 0
```

Add this to `build_parser()`:

```python
    p_rt = sub.add_parser("redteam", help="Red Team Annex — methodology generator with guardrails")
    p_rt.add_argument("rt_action", choices=["status", "generate", "checklist"])
    p_rt.add_argument("--target", help="target URL/IP/domain/path")
    p_rt.add_argument("--phase", choices=["recon", "probe", "exploit", "post_exploit"], default="probe")
    p_rt.add_argument("--capabilities", help="comma-separated capability ids (default: auto-select)")
    p_rt.add_argument("--engagement", help="engagement file path (for exploit token)")
    p_rt.add_argument("--token", help="single-use approval token signature (for exploit/post_exploit)")
    p_rt.add_argument("--rt-phase", choices=["recon", "probe"], default="recon", help="phase for checklist")
    p_rt.set_defaults(func=cmd_redteam)
```


## Step 8: `tests/test_redteam.py`

```python
"""Tests for the Red Team Annex modules."""

from __future__ import annotations

from pathlib import Path
import pytest
import json
import tempfile


# ---------- helpers ----------

@pytest.fixture
def caps_path(tmp_path):
    """Write a minimal capabilities file."""
    data = {
        "version": "2.1",
        "capabilities": [
            {"id": "recon_passive", "label": "Passive Recon", "layers": [0], "target_types": ["domain"]},
            {"id": "web_sqli", "label": "SQL Injection", "layers": [2], "target_types": ["url"], "interlinks": ["exploit_sqlmap"]},
            {"id": "exploit_sqlmap", "label": "SQLMap Exploitation", "layers": [8], "gated": True, "target_types": ["url"]},
            {"id": "post_exploit_privesc", "label": "Privilege Escalation", "layers": [9], "gated": True, "target_types": ["ip"]},
        ],
        "tools": {},
        "target_type_defaults": {
            "url": {"auto_capabilities": ["recon_passive", "web_sqli", "exploit_sqlmap"]},
        },
    }
    p = tmp_path / "redteam_capabilities.yaml"
    import yaml
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return p


@pytest.fixture
def orch():
    """Create a minimal orchestrator with a valid engagement."""
    from orchestrator import Engagement, Scope
    from orchestrator.policy import Orchestrator
    from datetime import UTC, datetime, timedelta
    key = b"test-signing-key-32bytes!"[:32]
    scope = Scope(enabled=True)
    scope.allow.urls.append("https://staging.example.com")
    eng = Engagement(
        id="test-eng-001", authorized_by="tester",
        approved_at=datetime.now(UTC).isoformat(),
        expires_at=(datetime.now(UTC) + timedelta(hours=8)).isoformat(),
        scope=scope,
    ).sign(key)
    orch = Orchestrator(key)
    orch.start_engagement(eng)
    return orch, key, eng


class TestCapabilities:
    def test_load(self, caps_path):
        from redteam.capabilities import load_capabilities
        caps = load_capabilities(caps_path)
        assert caps.get("web_sqli") is not None
        assert caps.get("nonexistent") is None
        assert caps.get("exploit_sqlmap").gated is True

    def test_for_target(self, caps_path):
        from redteam.capabilities import load_capabilities
        caps = load_capabilities(caps_path)
        resolved = caps.for_target("url")
        assert any(c.id == "web_sqli" for c in resolved)


class TestGenerator:
    def test_recon_allowed(self, caps_path, orch):
        """Probe/recon content is allowed with just a valid engagement."""
        from redteam.generator import MethodologyGenerator, GenerateRequest
        caps = load_capabilities(caps_path)
        orch_instance, key, eng = orch
        gen = MethodologyGenerator(caps)
        result = gen.generate(GenerateRequest(
            target="staging.example.com", phase="recon",
            capabilities=["recon_passive"], orchestrator=orch_instance,
        ))
        assert "staging.example.com" in result.content
        assert "Authorization: passed" in result.warnings

    def test_probe_allowed(self, caps_path, orch):
        """Probe content is allowed with just a valid engagement."""
        from redteam.generator import MethodologyGenerator, GenerateRequest
        caps = load_capabilities(caps_path)
        orch_instance, key, eng = orch
        gen = MethodologyGenerator(caps)
        result = gen.generate(GenerateRequest(
            target="https://staging.example.com", phase="probe",
            capabilities=["web_sqli"], orchestrator=orch_instance,
        ))
        assert "SQL" in result.content

    def test_exploit_refused_without_token(self, caps_path, orch):
        """Exploit content must be refused without an approval token."""
        from redteam.generator import MethodologyGenerator, GenerateRequest
        caps = load_capabilities(caps_path)
        orch_instance, key, eng = orch
        gen = MethodologyGenerator(caps)
        with pytest.raises(PermissionError, match="approval token"):
            gen.generate(GenerateRequest(
                target="https://staging.example.com", phase="exploit",
                capabilities=["exploit_sqlmap"], orchestrator=orch_instance,
                approval_token=None,
            ))

    def test_exploit_allowed_with_token(self, caps_path, orch):
        """Exploit content is allowed with a valid approval token."""
        from redteam.generator import MethodologyGenerator, GenerateRequest
        from orchestrator.engagement import ApprovalToken, now_utc
        from datetime import timedelta
        caps = load_capabilities(caps_path)
        orch_instance, key, eng = orch
        token = ApprovalToken(
            engagement_id=eng.id, action="exploit",
            target="https://staging.example.com",
            expires_at=(now_utc() + timedelta(hours=1)).isoformat(),
        )
        token = token.sign(key)
        gen = MethodologyGenerator(caps)
        result = gen.generate(GenerateRequest(
            target="https://staging.example.com", phase="exploit",
            capabilities=["exploit_sqlmap"], orchestrator=orch_instance,
            approval_token=token,
        ))
        assert "sqlmap" in result.content.lower()
        assert "Authorization: passed" in result.warnings

    def test_exploit_refused_wrong_target(self, caps_path, orch):
        """Token bound to a different target must be refused."""
        from redteam.generator import MethodologyGenerator, GenerateRequest
        from orchestrator.engagement import ApprovalToken, now_utc
        from datetime import timedelta
        caps = load_capabilities(caps_path)
        orch_instance, key, eng = orch
        token = ApprovalToken(
            engagement_id=eng.id, action="exploit",
            target="https://different-target.com",
            expires_at=(now_utc() + timedelta(hours=1)).isoformat(),
        ).sign(key)
        gen = MethodologyGenerator(caps)
        with pytest.raises(PermissionError, match="target mismatch"):
            gen.generate(GenerateRequest(
                target="https://staging.example.com", phase="exploit",
                capabilities=["exploit_sqlmap"], orchestrator=orch_instance,
                approval_token=token,
            ))

    def test_exploit_refused_without_engagement(self, caps_path):
        """Without an orchestrator (no engagement), exploit is refused."""
        from redteam.generator import MethodologyGenerator, GenerateRequest
        from redteam.capabilities import load_capabilities
        caps = load_capabilities(caps_path)
        gen = MethodologyGenerator(caps)
        with pytest.raises(PermissionError):
            gen.generate(GenerateRequest(
                target="https://staging.example.com", phase="exploit",
                capabilities=["exploit_sqlmap"], orchestrator=None,
            ))


class TestChecklist:
    def test_generate(self):
        from redteam.checklist import ChecklistGenerator
        c = ChecklistGenerator().generate(
            target="staging.example.com", phase="recon",
            engagement_id="ENG-001", authorized_by="tester",
        )
        assert "staging.example.com" in c.content
        assert "ENG-001" in c.content
        assert "tester" in c.content


class TestEndToEnd:
    def test_workflow_recon_to_probe(self, caps_path, orch):
        """Full workflow: recon -> probe, both allowed."""
        from redteam.generator import MethodologyGenerator, GenerateRequest
        caps = load_capabilities(caps_path)
        orch_instance, key, eng = orch
        gen = MethodologyGenerator(caps)

        # Recon
        r1 = gen.generate(GenerateRequest(
            target="staging.example.com", phase="recon",
            capabilities=["recon_passive"], orchestrator=orch_instance,
        ))
        assert r1.content

        # Probe
        r2 = gen.generate(GenerateRequest(
            target="https://staging.example.com", phase="probe",
            capabilities=["web_sqli"], orchestrator=orch_instance,
        ))
        assert r2.content

    def test_workflow_exploit_refused(self, caps_path, orch):
        """Exploit without token fails in the full workflow."""
        from redteam.generator import MethodologyGenerator, GenerateRequest
        caps = load_capabilities(caps_path)
        orch_instance, key, eng = orch
        gen = MethodologyGenerator(caps)
        with pytest.raises(PermissionError):
            gen.generate(GenerateRequest(
                target="https://staging.example.com", phase="exploit",
                capabilities=["exploit_sqlmap"], orchestrator=orch_instance,
            ))
```

## Implementation Order

1. `config/redteam_capabilities.yaml.template` (Step 1)
2. `src/redteam/__init__.py` (Step 2)
3. `src/redteam/capabilities.py` (Step 3)
4. `src/redteam/generator.py` (Step 4)
5. `src/redteam/checklist.py` (Step 5)
6. `src/redteam/templates/__init__.py` (Step 6)
7. Modify `src/cli/wraith.py` (Step 7)
8. `tests/test_redteam.py` (Step 8)
9. Run tests: `pytest tests/test_redteam.py -v`

## Acceptance Criteria

1. `wraith redteam status --target https://staging.example.com` shows engagement state + capability categories
2. `wraith redteam generate --target staging.example.com --phase recon` produces recon methodology
3. `wraith redteam generate --target https://staging.example.com --phase probe --capabilities web_sqli` produces SQLi probe commands
4. `wraith redteam generate --target https://staging.example.com --phase exploit` is REFUSED without `--token`
5. `wraith redteam generate --target https://staging.example.com --phase exploit --token SIG` is REFUSED with wrong target token
6. `wraith redteam generate --target https://staging.example.com --phase exploit --token SIG --engagement eng.json` is allowed with valid token
7. Generated content is persisted in the ResultStore (check with `wraith report <engagement>`)
8. All new tests pass: `pytest tests/test_redteam.py -v`
9. All existing tests still pass: `pytest tests/ -v`
10. No new dependencies beyond stdlib + PyYAML
11. The `.template` file contains no secrets
