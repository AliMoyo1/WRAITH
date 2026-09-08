"""Engagement validity and signing tests."""

from __future__ import annotations

from datetime import timedelta

from orchestrator import Engagement, Scope, ScopeList, now_utc

KEY = b"test-operator-key"


def _enabled_scope() -> Scope:
    return Scope(allow=ScopeList(domains=["example.com"]), enabled=True)


def _valid(key: bytes = KEY) -> Engagement:
    started = now_utc()
    return Engagement(
        id="e1",
        authorized_by="operator@org",
        approved_at=started.isoformat(),
        expires_at=(started + timedelta(hours=4)).isoformat(),
        scope=_enabled_scope(),
    ).sign(key)


def test_valid_engagement_passes():
    ok, reason = _valid().is_valid(KEY)
    assert ok is True, reason


def test_blank_approver_rejected():
    eng = _valid()
    eng.authorized_by = "   "
    eng.sign(KEY)
    ok, reason = eng.is_valid(KEY)
    assert ok is False and "authorized_by" in reason


def test_missing_timestamps_rejected():
    eng = _valid()
    eng.approved_at = ""
    eng.sign(KEY)
    ok, reason = eng.is_valid(KEY)
    assert ok is False and "approved_at" in reason


def test_expired_rejected():
    started = now_utc() - timedelta(hours=10)
    eng = Engagement(
        id="e2",
        authorized_by="op",
        approved_at=started.isoformat(),
        expires_at=(started + timedelta(hours=1)).isoformat(),
        scope=_enabled_scope(),
    ).sign(KEY)
    ok, reason = eng.is_valid(KEY)
    assert ok is False and "expired" in reason


def test_closed_rejected():
    eng = _valid()
    eng.open = False
    ok, reason = eng.is_valid(KEY)
    assert ok is False and "closed" in reason


def test_tampered_signature_rejected():
    eng = _valid()
    eng.authorized_by = "attacker"  # change a signed field without re-signing
    ok, reason = eng.is_valid(KEY)
    assert ok is False and "signature" in reason


def test_wrong_key_rejected():
    ok, reason = _valid().is_valid(b"different-key")
    assert ok is False and "signature" in reason


def test_scope_disabled_rejected():
    started = now_utc()
    eng = Engagement(
        id="e3",
        authorized_by="op",
        approved_at=started.isoformat(),
        expires_at=(started + timedelta(hours=1)).isoformat(),
        scope=Scope(allow=ScopeList(domains=["example.com"]), enabled=False),
    ).sign(KEY)
    ok, reason = eng.is_valid(KEY)
    assert ok is False and "scope" in reason
