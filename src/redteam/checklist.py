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
    """Generates pre-flight checklists for engagement phases."""

    def generate(
        self,
        target: str = "",
        phase: str = "recon",
        engagement_id: str = "",
        authorized_by: str = "",
    ) -> PreFlightChecklist:
        cid = str(uuid.uuid4())[:8]
        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        content = _CHECKLIST_TPL.format(
            phase=phase.capitalize(),
            checklist_id=cid,
            date=now,
            engagement_id=engagement_id or "(not set)",
            target=target or "(not set)",
            authorized_by=authorized_by or "Operator",
            sep="=" * 60,
        )
        return PreFlightChecklist(
            checklist_id=cid,
            target=target,
            phase=phase,
            engagement_id=engagement_id,
            authorized_by=authorized_by,
            content=content,
        )