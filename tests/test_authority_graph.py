"""Tests for the effective-authority graph: composition of the entitlement gate and
the engagement gate into one reachability picture, plus the CLI."""

from __future__ import annotations

import json

from authority_graph import build_authority_graph


def _reach(roles, tier):
    return build_authority_graph(roles, tier).to_dict()["reachability"]


def test_viewer_community_reaches_nothing_target_directed():
    reach = _reach(["viewer"], "community")
    assert reach["held_classes"] == ["control_plane_read"]
    assert reach["target_directed_classes"] == []
    assert reach["reachable_tracks"] == []
    assert reach["can_reach_consequential"] is False
    assert "redteam_exploit" in reach["blocked_classes"]


def test_analyst_pro_is_analysis_only():
    reach = _reach(["analyst"], "pro")
    assert set(reach["held_classes"]) == {
        "control_plane_read",
        "control_plane_scan",
        "redteam_recon",
        "redteam_probe",
    }
    assert reach["analysis_classes"] == ["control_plane_scan", "redteam_probe", "redteam_recon"]
    assert reach["consequential_classes"] == []
    assert reach["reachable_tracks"] == ["network_cloud", "sast_agentic", "web_api"]
    assert reach["can_reach_consequential"] is False


def test_operator_enterprise_reaches_consequential_with_token():
    reach = _reach(["operator"], "enterprise")
    assert "admin" not in reach["held_classes"]  # separation of duties
    assert reach["consequential_classes"] == ["redteam_exploit", "redteam_post_exploit"]
    assert reach["reachable_tracks"] == [
        "exploitation",
        "network_cloud",
        "post_exploit",
        "sast_agentic",
        "web_api",
    ]
    assert reach["can_reach_consequential"] is True
    assert reach["requires_single_use_token"] == ["exploitation", "post_exploit"]


def test_admin_is_administrative_not_target_directed():
    graph = build_authority_graph(["admin"], "community").to_dict()
    reach = graph["reachability"]
    assert set(reach["held_classes"]) == {"admin", "control_plane_read"}
    assert reach["target_directed_classes"] == []
    assert reach["reachable_tracks"] == []
    admin_activity = next(
        n for n in graph["nodes"] if n["kind"] == "activity" and n["activity"] == "administrative"
    )
    assert admin_activity["target_directed"] is False
    assert admin_activity["conditions"] == []


def test_entitlement_edge_reasons_granted_and_blocked():
    edges = {e["dst"]: e for e in build_authority_graph(["viewer"], "community").edges if e["gate"] == "entitlement"}
    granted = edges["control_plane_read"]
    assert granted["granted"] is True and "meets minimum" in granted["reason"]
    blocked = edges["redteam_exploit"]
    assert blocked["granted"] is False
    assert "below minimum" in blocked["reason"] and "no held role" in blocked["reason"]


def test_consequential_activity_conditions_include_token():
    graph = build_authority_graph(["operator"], "enterprise").to_dict()
    consequential = [n for n in graph["nodes"] if n.get("activity") == "consequential"]
    assert consequential  # exploitation and post-exploitation
    for node in consequential:
        assert node["conditions"] == ["scope", "open_engagement", "single_use_approval_token"]
    analysis = next(n for n in graph["nodes"] if n.get("activity") == "analysis")
    assert analysis["conditions"] == ["scope", "open_engagement"]


def test_nodes_include_principal_and_all_seven_classes():
    nodes = build_authority_graph(["operator"], "enterprise").nodes
    assert any(n["kind"] == "principal" for n in nodes)
    classes = {n["id"] for n in nodes if n["kind"] == "capability_class"}
    assert len(classes) == 7


def test_graph_is_deterministic():
    a = build_authority_graph(["operator", "admin"], "enterprise").to_dict()
    b = build_authority_graph(["admin", "operator"], "enterprise").to_dict()
    assert a == b


def test_bad_role_raises():
    import pytest

    with pytest.raises(ValueError):
        build_authority_graph(["wizard"], "community")


def test_cli_graph_summary(capsys):
    from cli import wraith

    assert wraith.main(["entitlement", "graph", "--roles", "operator", "--tier", "enterprise"]) == 0
    out = capsys.readouterr().out
    assert "can reach consequential: True" in out
    assert "exploitation" in out and "single_use_approval_token" in out


def test_cli_graph_json_out(tmp_path):
    from cli import wraith

    out = tmp_path / "graph.json"
    rc = wraith.main(
        ["entitlement", "graph", "--roles", "analyst", "--tier", "pro", "--json", "--out", str(out)]
    )
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["principal"]["tier"] == "pro"
    assert data["reachability"]["reachable_tracks"] == ["network_cloud", "sast_agentic", "web_api"]


def test_cli_graph_requires_roles_and_tier(capsys):
    from cli import wraith

    assert wraith.main(["entitlement", "graph", "--roles", "operator"]) == 2


def test_cli_graph_rejects_bad_role():
    from cli import wraith

    assert wraith.main(["entitlement", "graph", "--roles", "wizard", "--tier", "pro"]) == 2
