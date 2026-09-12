"""Tests for least-privilege recommendations (entitlement.recommend)."""

from __future__ import annotations

from entitlement import analyze_grant, minimal_roles_tier
from entitlement.policy import Role, Tier


def test_minimal_for_read_only():
    assert minimal_roles_tier(["control_plane_read"]) == (frozenset({Role.VIEWER}), Tier.COMMUNITY)


def test_minimal_for_scan_is_analyst_community():
    roles, tier = minimal_roles_tier(["control_plane_scan"])
    assert roles == frozenset({Role.ANALYST}) and tier == Tier.COMMUNITY


def test_minimal_for_exploit_needs_operator_enterprise():
    assert minimal_roles_tier(["redteam_exploit"]) == (frozenset({Role.OPERATOR}), Tier.ENTERPRISE)


def test_separation_of_duties_admin_and_exploit():
    roles, tier = minimal_roles_tier(["admin", "redteam_exploit"])
    assert roles == frozenset({Role.ADMIN, Role.OPERATOR}) and tier == Tier.ENTERPRISE


def test_ungrantable_class_returns_none():
    # api_key_manage is an issuance-context marker, never conferred by the matrix.
    assert minimal_roles_tier(["api_key_manage"]) is None


def test_analyze_flags_over_provisioning():
    report = analyze_grant(["operator"], "enterprise", ["control_plane_read"])
    assert report["over_provisioned"] is True
    assert "redteam_exploit" in report["unused"]
    assert report["missing"] == []
    assert report["recommended_roles"] == ["viewer"] and report["recommended_tier"] == "community"


def test_analyze_flags_missing():
    report = analyze_grant(["viewer"], "community", ["redteam_exploit"])
    assert "redteam_exploit" in report["missing"]
    assert report["recommended_roles"] == ["operator"] and report["recommended_tier"] == "enterprise"


def test_cli_recommend(capsys):
    from cli import wraith

    assert wraith.main(["entitlement", "recommend", "--needed", "control_plane_scan"]) == 0
    out = capsys.readouterr().out
    assert "analyst" in out and "community" in out


def test_cli_recommend_analyze_over_provisioned(capsys):
    from cli import wraith

    rc = wraith.main([
        "entitlement", "recommend", "--needed", "control_plane_read",
        "--roles", "operator", "--tier", "enterprise",
    ])
    assert rc == 0
    assert "over_provisioned: True" in capsys.readouterr().out


def test_cli_recommend_rejects_bad_role(capsys):
    from cli import wraith

    rc = wraith.main([
        "entitlement", "recommend", "--needed", "control_plane_read",
        "--roles", "wizard", "--tier", "enterprise",
    ])
    assert rc == 2
