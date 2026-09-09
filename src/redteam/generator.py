"""Methodology generator: every output path is gated by the kernel.

This module produces target-specific pentest methodology text. It does NOT
execute anything: it generates text that a human operator follows.

All output paths go through ``Orchestrator.require_authorization()``:

- Recon / Probe content: requires scope check + valid signed engagement
- Exploit / Post-Exploit content: additionally requires a single-use
  ``ApprovalToken`` that is consumed before any content is emitted

If no orchestrator is supplied, or a gated phase has no valid token,
PermissionError is raised and nothing is generated (fail closed).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .capabilities import Capabilities, Capability, load_capabilities

if TYPE_CHECKING:
    from orchestrator.engagement import ApprovalToken
    from orchestrator.policy import Orchestrator


@dataclass
class GenerateRequest:
    """A request to generate methodology text.

    For exploit / post_exploit phases, ``approval_token`` must be provided
    and will be consumed by the orchestrator. Without it, generation is
    refused with a PermissionError.
    """

    target: str = ""
    target_type: str = ""
    phase: str = "probe"
    capabilities: list[str] | None = None
    engagement_id: str = ""
    approval_token: ApprovalToken | None = None
    orchestrator: Orchestrator | None = None


@dataclass
class GenerateResult:
    """The generated methodology text and metadata."""

    content: str = ""
    phase: str = ""
    target: str = ""
    target_type: str = ""
    engagement_id: str = ""
    finding_id: str = ""
    warnings: list[str] = field(default_factory=list)


_EXPLOIT_WARNING = """
╔══════════════════════════════════════════════════════════════════════════╗
║  WRAITH Red Team Annex: EXPLOIT / POST-EXPLOIT CONTENT                ║
║  This content is authorised only for the specific engagement and       ║
║  target listed below. Unauthorized use is illegal.                     ║
║  Approval token consumed: {token_sig}                                  ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

# Mapping from CLI phase name to canonical taxonomy layers
_PHASE_LAYERS = {
    "recon": [0, 1],
    "probe": [2, 3, 4, 5, 6, 7],
    "exploit": [8],
    "post_exploit": [9],
}


class MethodologyGenerator:
    """Generates methodology text. Gated by the kernel authorization model."""

    def __init__(self, caps: Capabilities | None = None):
        self._caps = caps or load_capabilities()

    def generate(self, request: GenerateRequest) -> GenerateResult:
        """Generate methodology for the given request.

        Raises PermissionError if not authorized: no content is emitted
        without a cleared gate. A missing orchestrator is treated as
        unauthorized (fail closed), never as a bypass.
        """
        result = GenerateResult(
            phase=request.phase,
            target=request.target,
            target_type=request.target_type or "generic",
            engagement_id=request.engagement_id,
        )

        # ---- Kernel authorization check (fail closed) ----

        orch = request.orchestrator
        if orch is None:
            raise PermissionError(
                "no engagement: an orchestrator with an open engagement is "
                "required to generate methodology"
            )

        from orchestrator.policy import Track

        if request.phase in ("exploit", "post_exploit"):
            track = (
                Track.EXPLOITATION
                if request.phase == "exploit"
                else Track.POST_EXPLOIT
            )
            orch.require_authorization(track, request.target, request.approval_token)
        else:
            # Recon / probe still require a scope check + valid engagement
            orch.require_authorization(Track.WEB_API, request.target, None)

        result.warnings.append("Authorization: ***")

        # ---- Build content ----

        lines = [
            f"== WRAITH Red Team Annex: {request.phase.capitalize()} ==",
            f"  Target: {request.target}",
            f"  Engagement: {request.engagement_id}",
            "",
        ]

        # Warning banner for exploit / post_exploit
        if request.phase in ("exploit", "post_exploit") and request.approval_token:
            token_sig = request.approval_token.signature or "(consumed)"
            lines.append(_EXPLOIT_WARNING.format(token_sig=token_sig))

        # Resolve capabilities
        cap_ids = request.capabilities or []
        caps: list[Capability] = [c for cid in cap_ids if (c := self._caps.get(cid))]

        if not caps:
            lines.append(
                "  No specific capabilities selected. Generating general methodology.\n"
            )

        # Filter by phase layer range
        allowed_layers = _PHASE_LAYERS.get(request.phase, [])
        phase_caps = [
            c for c in caps if any(layer in allowed_layers for layer in c.layers)
        ]

        target = self._safe_target(request.target)
        for cap in phase_caps:
            lines.append("")
            lines.append(f"  === {cap.label} ===")
            lines.append(f"  Layers: {cap.layers}")
            if cap.tools:
                lines.append(f"  Tools: {', '.join(cap.tools)}")
            if cap.detection_domains:
                lines.append(f"  Detection domains: {', '.join(cap.detection_domains)}")
            if cap.gated:
                lines.append("  [GATED: requires approval token]")
            lines.append("")

            self._emit_methodology(lines, cap, request.phase, request.target_type, target)

            # --- Interlinks (attack-chain hints) ---
            linked = [
                link_cap for link in cap.interlinks if (link_cap := self._caps.get(link))
            ]
            if linked:
                names = ", ".join(link_cap.label for link_cap in linked)
                lines.append(f"    -> Next: {names}")

        result.content = "\n".join(lines)
        return result

    @staticmethod
    def _emit_methodology(
        lines: list[str], cap: Capability, phase: str, target_type: str, target: str
    ) -> None:
        """Append the layer-specific methodology lines for one capability.

        ``target`` is already scheme-stripped. All content is reference text
        for a human operator; nothing here is executed.
        """
        if cap.id == "recon_passive" and phase == "recon":
            lines.append(f"    curl -s 'https://crt.sh/?q=%25.{target}&output=json'")
            lines.append(f"    whois {target}")
            lines.append(f"    dig {target} ANY")

        elif cap.id == "recon_active" and phase == "recon":
            if target_type != "repo_path":
                lines.append(f"    nmap -sV -sC -T4 {target}")

        elif phase == "probe":
            if cap.id == "web_sqli":
                lines.append("    Payloads: ', \", ), '), \\\"))")
                lines.append("    WAF bypass: /**/OR/**/1=1, %27%20OR%201=1")
                lines.append(f"    curl -s '{target}?id=1'")
                lines.append(f"    curl -s '{target}?id=1%27'")
            elif cap.id == "web_xss":
                lines.append("    Payload: <script>alert(1)</script>")
                lines.append(f"    curl -s '{target}?q=<script>alert(1)</script>'")
            elif cap.id == "web_ssrf":
                lines.append("    Payload: ?url=http://169.254.169.254/latest/meta-data/")
                lines.append(f"    curl -s '{target}?url=http://169.254.169.254/'")
            elif cap.id == "web_path_traversal":
                lines.append("    Payload: ../../../etc/passwd")
                lines.append(f"    curl -s '{target}?file=../../../etc/passwd'")
            elif cap.id == "api_idor":
                lines.append("    Test: replace /users/123 with /users/456")
                lines.append("    Check horizontal & vertical access controls")
            elif cap.id == "api_jwt":
                lines.append("    Check: alg=none, algorithm confusion, expired tokens")
                lines.append("    Tools: jwt_tool, jwt-cracker")
            elif cap.id == "api_graphql":
                query = '{"query":"{__schema{types{name}}}"}'
                lines.append(f"    curl -X POST '{target}/graphql' \\")
                lines.append(f"      -H 'Content-Type: application/json' -d '{query}'")
            elif cap.id == "network_scan":
                lines.append(f"    nmap -sV -sC -p- {target}")

        elif phase == "exploit":
            if cap.id == "exploit_sqlmap":
                lines.append(f"    sqlmap -u '{target}' --batch --dbs --stop=5")
            elif cap.id == "exploit_metasploit":
                lines.append(f"    msfconsole -q -x 'search {target}'")
            elif cap.id == "exploit_hydra":
                lines.append(
                    f"    hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://{target}"
                )
            elif cap.id == "exploit_ad":
                lines.append(f"    bloodhound-python -d domain.local -c All -ns {target}")
                lines.append(f"    impacket-secretsdump domain.local/user:'pass'@{target}")

        elif phase == "post_exploit":
            if cap.id == "post_exploit_privesc":
                lines.append("    Linux: find / -perm -4000 -type f 2>/dev/null")
                lines.append("    Linux: sudo -l")
                lines.append("    Linux: cat /etc/shadow 2>/dev/null")
                lines.append("    Windows: whoami /priv")
                lines.append("    Windows: icacls C:\\Windows\\Temp")
            elif cap.id == "post_exploit_lateral":
                lines.append(
                    f"    bloodhound-python -u 'DOMAIN\\user' -p 'password' -ns {target}"
                )
                lines.append(f"    impacket-psexec domain.local/user:'pass'@{target}")

    @staticmethod
    def _safe_target(target: str) -> str:
        """Remove protocol prefix for cleaner command output."""
        for prefix in ("https://", "http://"):
            if target.startswith(prefix):
                return target[len(prefix):]
        return target
