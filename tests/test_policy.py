"""Orchestrator enforcement tests: routing, gates, tokens, kill-switch."""

from __future__ import annotations

from datetime import timedelta

import pytest

from orchestrator import ApprovalToken, Engagement, Orchestrator, Scope, ScopeList, Track, now_utc

KEY = b"test-operator-key"
TARGET = "https://example.com/app"


def _orch_with_engagement() -> Orchestrator:
    started = now_utc()
    eng = Engagement(
        id="e1",
        authorized_by="operator",
        approved_at=started.isoformat(),
        expires_at=(started + timedelta(hours=4)).isoformat(),
        scope=Scope(allow=ScopeList(domains=["example.com"]), enabled=True),
    ).sign(KEY)
    orch = Orchestrator(KEY)
    orch.start_engagement(eng)
    return orch


def _token(action: str, target: str = TARGET, key: bytes = KEY) -> ApprovalToken:
    return ApprovalToken(
        engagement_id="e1",
        action=action,
        target=target,
        expires_at=(now_utc() + timedelta(minutes=10)).isoformat(),
    ).sign(key)


def test_orchestrator_requires_key():
    with pytest.raises(ValueError):
        Orchestrator(b"")


def test_route_requires_open_engagement():
    orch = Orchestrator(KEY)
    with pytest.raises(PermissionError):
        orch.route("web_vuln", TARGET)


def test_route_rejects_out_of_scope():
    orch = _orch_with_engagement()
    with pytest.raises(PermissionError):
        orch.route("web_vuln", "https://not-in-scope.test/x")


def test_route_does_not_escalate_without_token():
    orch = _orch_with_engagement()
    result = orch.route("web_vuln", TARGET)
    assert Track.WEB_API in result.tracks
    assert Track.EXPLOITATION not in result.tracks
    assert result.pending_authorization and result.pending_authorization[0][0] is Track.EXPLOITATION


def test_route_escalates_with_valid_token():
    orch = _orch_with_engagement()
    result = orch.route("web_vuln", TARGET, token=_token("exploit"))
    assert Track.EXPLOITATION in result.tracks
    assert result.pending_authorization == []


def test_analysis_track_needs_no_token():
    orch = _orch_with_engagement()
    orch.require_authorization(Track.SAST_AGENTIC, TARGET)  # must not raise


def test_token_single_use():
    orch = _orch_with_engagement()
    token = _token("exploit")
    orch.require_authorization(Track.EXPLOITATION, TARGET, token)
    with pytest.raises(PermissionError):
        orch.require_authorization(Track.EXPLOITATION, TARGET, token)  # replay


def test_token_target_binding():
    orch = _orch_with_engagement()
    # Token minted for a different in-scope target must not authorize this one.
    bad = _token("exploit", target="https://example.com/other")
    with pytest.raises(PermissionError):
        orch.require_authorization(Track.EXPLOITATION, TARGET, bad)


def test_token_action_binding():
    orch = _orch_with_engagement()
    with pytest.raises(PermissionError):
        orch.require_authorization(Track.EXPLOITATION, TARGET, _token("post_exploit"))


def test_token_wrong_key_rejected():
    orch = _orch_with_engagement()
    with pytest.raises(PermissionError):
        orch.require_authorization(Track.EXPLOITATION, TARGET, _token("exploit", key=b"other"))


def test_kill_switch_blocks_everything():
    orch = _orch_with_engagement()
    orch.kill()
    with pytest.raises(PermissionError):
        orch.route("web_vuln", TARGET)
    with pytest.raises(PermissionError):
        orch.require_authorization(Track.SAST_AGENTIC, TARGET)
