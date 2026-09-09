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