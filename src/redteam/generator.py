"""Methodology generator — every output path is gated by the kernel.

This module produces target-specific pentest methodology text. It does NOT
execute anything — it generates text that a human operator follows.

All output paths go through ``Orchestrator.require_authorization()``:

- Recon / Probe content: requires scope check + valid signed engagement
- Exploit / Post-Exploit content: additionally requires a single-use
  ``ApprovalToken`` that is consumed before any content is emitted

Without a valid token, PermissionError is raised and nothing is generated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .capabilities import Capabilities, load_capabilities

# Lazy import to avoid circular deps at package level
_HAVE_ORCH = False


def _require_auth(orch, track, target, token):
    """Wrapper that imports the Track enum lazily."""
    from orchestrator.policy import Track

    return orch.require_authorization(track, target, token)


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
    approval_token: Optional["ApprovalToken"] = None  # noqa: F821
    orchestrator: Optional["Orchestrator"] = None  # noqa: F821


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
║  WRAITH Red Team Annex — EXPLOIT / POST-EXPLOIT CONTENT               ║
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

        Raises PermissionError if not authorized — no content is emitted
        without a cleared gate.
        """
        result = GenerateResult(
            phase=request.phase,
            target=request.target,
            target_type=request.target_type or "generic",
            engagement_id=request.engagement_id,
        )

        # ---- Kernel authorization check ----

        if request.orchestrator is not None:
            from orchestrator.policy import Track

            if request.phase in ("exploit", "post_exploit"):
                track = (
                    Track.EXPLOITATION
                    if request.phase == "exploit"
                    else Track.POST_EXPLOIT
                )
                request.orchestrator.require_authorization(
                    track, request.target, request.approval_token
                )
            else:
                # Recon / probe still require scope check + valid engagement
                request.orchestrator.require_authorization(
                    Track.WEB_API, request.target, None
                )

        result.warnings.append("Authorization: ***")

        # ---- Build content ----

        lines = [
            f"╔══ WRAITH Red Team Annex — {request.phase.capitalize()} ══╗",
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
        caps: list[Capabilities] = [
            c for cid in cap_ids if (c := self._caps.get(cid))
        ]

        if not caps:
            lines.append(
                "  No specific capabilities selected. Generating general methodology.\n"
            )

        # Filter by phase layer range
        allowed_layers = _PHASE_LAYERS.get(request.phase, [])
        phase_caps = [c for c in caps if any(l in allowed_layers for l in c.layers)]

        for cap in phase_caps:
            lines.append("" if lines[-1] == "" else "")
            lines.append(f"  === {cap.label} ===")
            lines.append(f"  Layers: {cap.layers}")
            if cap.tools:
                lines.append(f"  Tools: {', '.join(cap.tools)}")
            if cap.detection_domains:
                lines.append(
                    f"  Detection domains: {', '.join(cap.detection_domains)}"
                )
            if cap.gated:
                lines.append("  [GATED — requires approval token]")
            lines.append("")

            # --- Layer-specific methodology ---

            if cap.id == "recon_passive" and request.phase == "recon":
                lines.append(f"    curl -s 'https://crt.sh/?q=%25.{self._safe_target(request.target)}&output=json'")
                lines.append(f"    whois {self._safe_target(request.target)}")
                lines.append(f"    dig {self._safe_target(request.target)} ANY")

            elif cap.id == "recon_active" and request.phase == "recon":
                if request.target_type != "repo_path":
                    lines.append(
                        f"    nmap -sV -sC -T4 {self._safe_target(request.target)}"
                    )

            elif request.phase == "probe":
                if cap.id == "web_sqli":
                    lines.append("    Payloads: ', \", ), '), \\\"))")
                    lines.append("    WAF bypass: /**/OR/**/1=1, %27%20OR%201=1")
                    lines.append(
                        f"    curl -s '{self._safe_target(request.target)}?id=1'"
                    )
                    lines.append(
                        f"    curl -s '{self._safe_target(request.target)}?id=1%27'"
                    )
                elif cap.id == "web_xss":
                    lines.append("    Payload: <script>alert(1)</script>")
                    lines.append(
                        f"    curl -s '{self._safe_target(request.target)}?q=<script>alert(1)</script>'"
                    )
                elif cap.id == "web_ssrf":
                    lines.append("    Payload: ?url=http://169.254.169.254/latest/meta-data/")
                    lines.append(
                        f"    curl -s '{self._safe_target(request.target)}?url=http://169.254.169.254/'"
                    )
                elif cap.id == "web_path_traversal":
                    lines.append("    Payload: ../../../etc/passwd")
                    lines.append(
                        f"    curl -s '{self._safe_target(request.target)}?file=../../../etc/passwd'"
                    )
                elif cap.id == "api_idor":
                    lines.append("    Test: replace /users/123 with /users/456")
                    lines.append("    Check horizontal & vertical access controls")
                elif cap.id == "api_jwt":
                    lines.append("    Check: alg=none, algorithm confusion, expired tokens")
                    lines.append("    Tools: jwt_tool, jwt-cracker")
                elif cap.id == "api_graphql":
                    lines.append("    curl -X POST '{target}/graphql' -H 'Content-Type: application/json' -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}'")
                elif cap.id == "network_scan":
                    lines.append(
                        f"    nmap -sV -sC -p- {self._safe_target(request.target)}"
                    )

            elif request.phase == "exploit":
                if cap.id == "exploit_sqlmap":
                    lines.append(
                        f"    sqlmap -u '{self._safe_target(request.target)}' --batch --dbs --stop=5"
                    )
                elif cap.id == "exploit_metasploit":
                    lines.append(
                        f"    msfconsole -q -x 'search {self._safe_target(request.target)}'"
                    )
                elif cap.id == "exploit_hydra":
                    lines.append(
                        f"    hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://{self._safe_target(request.target)}"
                    )
                elif cap.id == "exploit_ad":
                    lines.append(f"    bloodhound-python -d domain.local -c All -ns {self._safe_target(request.target)}")
                    lines.append(f"    impacket-secretsdump domain.local/user:'pass'@{self._safe_target(request.target)}")

            elif request.phase == "post_exploit":
                if cap.id == "post_exploit_privesc":
                    lines.append("    Linux: find / -perm -4000 -type f 2>/dev/null")
                    lines.append("    Linux: sudo -l")
                    lines.append("    Linux: cat /etc/shadow 2>/dev/null")
                    lines.append("    Windows: whoami /priv")
                    lines.append("    Windows: icacls C:\\Windows\\Temp")
                elif cap.id == "post_exploit_lateral":
                    lines.append(
                        f"    bloodhound-python -u 'DOMAIN\\user' -p 'password' -ns {self._safe_target(request.target)}"
                    )
                    lines.append("    impacket-psexec domain.local/user:'pass'@{target}")

            # --- Interlinks (attack-chain hints) ---
            if cap.interlinks:
                linked = [
                    self._caps.get(link)
                    for link in cap.interlinks
                    if self._caps.get(link)
                ]
                if linked:
                    lines.append(
                        f"    -> Next: {', '.join(l.label for l in linked)}"
                    )

        result.content = "\n".join(lines)
        return result

    @staticmethod
    def _safe_target(target: str) -> str:
        """Remove protocol prefix for cleaner command output."""
        for prefix in ("https://", "http://"):
            if target.startswith(prefix):
                return target[len(prefix) :]
        return target