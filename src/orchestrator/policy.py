"""WRAITH orchestrator: dependency-aware routing with enforced authorization.

This is the enforcement point. Every engine invocation is gated by scope and an
open, signed, unexpired engagement. Exploitation and post-exploitation (the
Layer 8-9 consequential actions) additionally require a valid, single-use,
target-bound approval token. route() never silently escalates to exploitation:
it includes an exploitation track only when authorization actually succeeds, and
otherwise reports it as pending with a reason.

Implements the routing rules from WRAITH.md Section 3.1 and the authorization
model from WRAITH.md Section 11.1.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from .engagement import ApprovalToken, Engagement


class Track(Enum):
    WEB_API = "web_api"            # Track A
    NETWORK_CLOUD = "network_cloud"  # Track B
    SAST_AGENTIC = "sast_agentic"    # Track C
    EXPLOITATION = "exploitation"    # consequential (Layer 8)
    POST_EXPLOIT = "post_exploit"    # consequential (Layer 9)


_CONSEQUENTIAL = (Track.EXPLOITATION, Track.POST_EXPLOIT)
_ACTION_FOR = {Track.EXPLOITATION: "exploit", Track.POST_EXPLOIT: "post_exploit"}

# finding_type -> analysis track
_ANALYSIS_ROUTE = {
    "web_vuln": Track.WEB_API,
    "api_issue": Track.WEB_API,
    "network_service": Track.NETWORK_CLOUD,
    "cloud_exposure": Track.NETWORK_CLOUD,
    "agentic_risk": Track.SAST_AGENTIC,
    "code_issue": Track.SAST_AGENTIC,
}
# finding_type -> consequential track it may escalate to (subject to authorization)
_ESCALATION_ROUTE = {
    "web_vuln": Track.EXPLOITATION,
    "api_issue": Track.EXPLOITATION,
    "network_service": Track.EXPLOITATION,
    "cloud_exposure": Track.EXPLOITATION,
    "agentic_risk": Track.POST_EXPLOIT,
}


@dataclass
class RouteResult:
    tracks: list[Track] = field(default_factory=list)
    pending_authorization: list[tuple[Track, str]] = field(default_factory=list)


class Orchestrator:
    """Routes findings to engines by dependency, enforcing authorization."""

    def __init__(self, signing_key: bytes):
        if not signing_key:
            raise ValueError("signing_key is required; do not run with a default key")
        self._key = signing_key
        self.engagement: Engagement | None = None
        self._consumed: set[str] = set()
        self.killed = False

    # engagement lifecycle -------------------------------------------------
    def start_engagement(self, engagement: Engagement, at: datetime | None = None) -> None:
        ok, reason = engagement.is_valid(self._key, at)
        if not ok:
            raise PermissionError(f"cannot start engagement: {reason}")
        self.engagement = engagement

    def close_engagement(self) -> None:
        if self.engagement:
            self.engagement.open = False
        self.engagement = None

    def kill(self) -> None:
        """Emergency stop. All authorization is refused until re-armed."""
        self.killed = True
        self.close_engagement()

    # enforcement ----------------------------------------------------------
    def _require_active_scope(self, target: str, at: datetime | None = None) -> Engagement:
        if self.killed:
            raise PermissionError("kill-switch engaged; all engine invocation refused")
        eng = self.engagement
        if eng is None or not eng.open:
            raise PermissionError("no open engagement (WRAITH.md 11.1)")
        ok, reason = eng.is_valid(self._key, at)
        if not ok:
            raise PermissionError(f"engagement invalid: {reason} (WRAITH.md 11.1)")
        if not eng.scope.allows(target):
            raise PermissionError(f"target out of scope: {target} (WRAITH.md 11.1)")
        return eng

    def require_authorization(
        self,
        track: Track,
        target: str,
        token: ApprovalToken | None = None,
        at: datetime | None = None,
    ) -> None:
        """Raise PermissionError unless invoking `track` on `target` is authorized.

        Every track requires scope plus an open, valid engagement. Consequential
        tracks additionally require a valid, single-use, target-bound token.
        """
        eng = self._require_active_scope(target, at)
        if track not in _CONSEQUENTIAL:
            return
        if token is None:
            raise PermissionError(f"{track.value} requires an action approval token (WRAITH.md 11.1)")
        if not token.verify(self._key):
            raise PermissionError("approval token signature invalid")
        assert token.signature is not None  # guaranteed by verify()
        if token.signature in self._consumed:
            raise PermissionError("approval token already used (replay refused)")
        if token.engagement_id != eng.id:
            raise PermissionError("approval token not bound to the current engagement")
        if token.action != _ACTION_FOR[track]:
            raise PermissionError(f"approval token action mismatch: {token.action}")
        if token.target != target:
            raise PermissionError("approval token target mismatch")
        if token.is_expired(at):
            raise PermissionError("approval token expired")
        self._consumed.add(token.signature)  # single use

    def route(
        self,
        finding_type: str,
        target: str,
        token: ApprovalToken | None = None,
        at: datetime | None = None,
    ) -> RouteResult:
        """Route a finding to tracks. Exploitation is included only if authorized."""
        self._require_active_scope(target, at)  # gate every routing decision
        result = RouteResult()
        analysis = _ANALYSIS_ROUTE.get(finding_type)
        if analysis is not None:
            result.tracks.append(analysis)
        escalation = _ESCALATION_ROUTE.get(finding_type)
        if escalation is not None:
            try:
                self.require_authorization(escalation, target, token, at)
                result.tracks.append(escalation)
            except PermissionError as exc:
                result.pending_authorization.append((escalation, str(exc)))
        return result
