"""WRAITH orchestrator - dependency-aware routing between engines.

Phase 0 skeleton. Implements the routing rules from WRAITH.md section 3.1
(Dependencies & Routing Rules) and the scope/authorization primitives
from section 11.1 (Authorization / Rules of Engagement).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Track(Enum):
    WEB_API = "web_api"          # Track A - Phases 1
    NETWORK_CLOUD = "network_cloud"  # Track B - Phase 2
    SAST_AGENTIC = "sast_agentic"    # Track C - Phase 3
    EXPLOITATION = "exploitation"    # Phase 4
    POST_EXPLOIT = "post_exploit"    # Phase 5


@dataclass
class Scope:
    """Signed allowlist of authorized targets. Empty = nothing in scope."""

    cidrs: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    repo_paths: list[str] = field(default_factory=list)
    enabled: bool = False

    def allows(self, target: str) -> bool:
        """Check whether a target is within the authorized scope.

        Phase 0 implementation is a prefix/substring match. Later phases
        replace this with proper CIDR and URL pattern matching.
        """
        if not self.enabled:
            return False  # Safe default: nothing authorized until scope is enabled
        return any(
            target.startswith(prefix)
            for prefix in self.cidrs + self.domains + self.urls + self.repo_paths
        )


@dataclass
class Engagement:
    """Per-session authorization record. Required before Layers 8-9."""

    id: str
    authorized_by: str
    approved_at: str
    scope: Scope
    open: bool = True


class Orchestrator:
    """Routes findings to the right engine by dependency, not position."""

    def __init__(self):
        self.engagement: Optional[Engagement] = None

    def start_engagement(self, engagement: Engagement) -> None:
        self.engagement = engagement

    def close_engagement(self) -> None:
        if self.engagement:
            self.engagement.open = False
        self.engagement = None

    def require_authorization(self, track: Track) -> None:
        """Hard gate for Layers 8-9 (exploitation / post-exploit).

        Raises PermissionError unless an open, approved engagement exists
        and the scope allowlist is enabled.
        """
        if track not in (Track.EXPLOITATION, Track.POST_EXPLOIT):
            return
        if not self.engagement or not self.engagement.open:
            raise PermissionError("No open engagement - exploitation requires authorization (WRAITH.md 11.1)")
        if not self.engagement.scope.enabled:
            raise PermissionError("Scope allowlist not enabled - exploitation refused (WRAITH.md 11.2)")

    def route(self, finding_type: str, target: str) -> list[Track]:
        """Determine which tracks should process a finding type for a target.

        Implements the routing conditions from WRAITH.md 3.1.
        """
        if not self.engagement or not self.engagement.scope.allows(target):
            raise PermissionError(f"Target {target} is out of scope")

        routing: list[Track] = []
        if finding_type in ("web_vuln", "api_issue"):
            routing.append(Track.WEB_API)
        elif finding_type in ("network_service", "cloud_exposure"):
            routing.append(Track.NETWORK_CLOUD)
        elif finding_type in ("agentic_risk", "code_issue"):
            routing.append(Track.SAST_AGENTIC)
        if finding_type in ("web_vuln", "api_issue", "network_service", "cloud_exposure"):
            routing.append(Track.EXPLOITATION)  # findings feed exploitation
        return routing
