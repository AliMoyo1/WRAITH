"""Tests for the Red Team Annex modules.

Tests the authorization model:
- Recon/Probe allowed with valid engagement
- Exploit/Post-Exploit refused without approval token
- Exploit/Post-Exploit allowed with valid token
- Exploit refused with wrong-target token
- Exploit refused without engagement (orchestrator)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

# ---------- Fixtures ----------


@pytest.fixture
def caps_path(tmp_path: Path) -> Path:
    """Write a minimal capabilities file for testing."""
    import yaml

    data = {
        "version": "2.1",
        "capabilities": [
            {
                "id": "recon_passive",
                "label": "Passive Recon",
                "layers": [0],
                "target_types": ["domain"],
            },
            {
                "id": "web_sqli",
                "label": "SQL Injection",
                "layers": [2],
                "target_types": ["url"],
                "interlinks": ["exploit_sqlmap"],
            },
            {
                "id": "exploit_sqlmap",
                "label": "SQLMap Exploitation",
                "layers": [8],
                "gated": True,
                "target_types": ["url"],
            },
            {
                "id": "post_exploit_privesc",
                "label": "Privilege Escalation",
                "layers": [9],
                "gated": True,
                "target_types": ["ip"],
            },
        ],
        "tools": {},
        "target_type_defaults": {
            "url": {"auto_capabilities": ["recon_passive", "web_sqli", "exploit_sqlmap"]},
            "domain": {"auto_capabilities": ["recon_passive"]},
            "ip": {"auto_capabilities": ["post_exploit_privesc"]},
        },
    }
    p = tmp_path / "redteam_capabilities.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return p


@pytest.fixture
def orch():
    """Create a minimal orchestrator with a valid engagement."""
    from orchestrator import Engagement, Scope
    from orchestrator.policy import Orchestrator

    key = b"test-signing-key-32bytes!"[:32]
    scope = Scope(enabled=True)
    scope.allow.urls.append("https://staging.example.com")
    eng = Engagement(
        id="test-eng-001",
        authorized_by="tester",
        approved_at=datetime.now(UTC).isoformat(),
        expires_at=(datetime.now(UTC) + timedelta(hours=8)).isoformat(),
        scope=scope,
    ).sign(key)
    orch = Orchestrator(key)
    orch.start_engagement(eng)
    return orch, key, eng


# ---------- Test capability loading ----------


class TestCapabilities:
    """Test routing table loading and resolution."""

    def test_load(self, caps_path):
        from redteam.capabilities import load_capabilities

        caps = load_capabilities(caps_path)
        assert caps.get("web_sqli") is not None
        assert caps.get("nonexistent") is None
        assert caps.get("exploit_sqlmap").gated is True

    def test_for_target(self, caps_path):
        from redteam.capabilities import load_capabilities

        caps = load_capabilities(caps_path)
        resolved = caps.for_target("url")
        assert any(c.id == "web_sqli" for c in resolved)

    def test_gated_capabilities(self, caps_path):
        from redteam.capabilities import load_capabilities

        caps = load_capabilities(caps_path)
        gated = caps.gated_capabilities()
        assert any(c.id == "exploit_sqlmap" for c in gated)
        assert not any(c.id == "recon_passive" for c in gated)

    def test_detect_target_type(self):
        from redteam.capabilities import detect_target_type

        assert detect_target_type("https://example.com") == "url"
        assert detect_target_type("https://api.example.com") == "api"
        assert detect_target_type("192.168.1.1") == "ip"
        assert detect_target_type("example.com") == "domain"
        assert detect_target_type("/repo/path") == "repo_path"
        assert detect_target_type("") == "generic"


# ---------- Test generator authorization ----------


class TestGeneratorAuthorization:
    """Test that the generator correctly enforces the authorization model."""

    def test_recon_allowed(self, caps_path, orch):
        """Recon content is allowed with just a valid engagement."""
        from redteam.capabilities import load_capabilities
        from redteam.generator import GenerateRequest, MethodologyGenerator

        caps = load_capabilities(caps_path)
        orch_instance, key, eng = orch
        gen = MethodologyGenerator(caps)
        result = gen.generate(
            GenerateRequest(
                target="https://staging.example.com",
                phase="recon",
                capabilities=["recon_passive"],
                orchestrator=orch_instance,
            )
        )
        assert "staging.example.com" in result.content
        assert "Authorization: ***" in result.warnings

    def test_probe_allowed(self, caps_path, orch):
        """Probe content is allowed with just a valid engagement."""
        from redteam.capabilities import load_capabilities
        from redteam.generator import GenerateRequest, MethodologyGenerator

        caps = load_capabilities(caps_path)
        orch_instance, key, eng = orch
        gen = MethodologyGenerator(caps)
        result = gen.generate(
            GenerateRequest(
                target="https://staging.example.com",
                phase="probe",
                capabilities=["web_sqli"],
                orchestrator=orch_instance,
            )
        )
        assert "SQL" in result.content

    def test_exploit_refused_without_token(self, caps_path, orch):
        """Exploit content must be refused without an approval token."""
        from redteam.capabilities import load_capabilities
        from redteam.generator import GenerateRequest, MethodologyGenerator

        caps = load_capabilities(caps_path)
        orch_instance, key, eng = orch
        gen = MethodologyGenerator(caps)
        with pytest.raises(PermissionError, match="approval token"):
            gen.generate(
                GenerateRequest(
                    target="https://staging.example.com",
                    phase="exploit",
                    capabilities=["exploit_sqlmap"],
                    orchestrator=orch_instance,
                    approval_token=None,
                )
            )

    def test_exploit_allowed_with_token(self, caps_path, orch):
        """Exploit content is allowed with a valid approval token."""
        from datetime import timedelta

        from orchestrator.engagement import ApprovalToken, now_utc
        from redteam.capabilities import load_capabilities
        from redteam.generator import GenerateRequest, MethodologyGenerator

        caps = load_capabilities(caps_path)
        orch_instance, key, eng = orch
        token = ApprovalToken(
            engagement_id=eng.id,
            action="exploit",
            target="https://staging.example.com",
            expires_at=(now_utc() + timedelta(hours=1)).isoformat(),
        )
        token = token.sign(key)
        gen = MethodologyGenerator(caps)
        result = gen.generate(
            GenerateRequest(
                target="https://staging.example.com",
                phase="exploit",
                capabilities=["exploit_sqlmap"],
                orchestrator=orch_instance,
                approval_token=token,
            )
        )
        assert "sqlmap" in result.content.lower()
        assert "Authorization: ***" in result.warnings

    def test_exploit_refused_wrong_target(self, caps_path, orch):
        """Token bound to a different target must be refused."""
        from datetime import timedelta

        from orchestrator.engagement import ApprovalToken, now_utc
        from redteam.capabilities import load_capabilities
        from redteam.generator import GenerateRequest, MethodologyGenerator

        caps = load_capabilities(caps_path)
        orch_instance, key, eng = orch
        token = ApprovalToken(
            engagement_id=eng.id,
            action="exploit",
            target="https://different-target.com",
            expires_at=(now_utc() + timedelta(hours=1)).isoformat(),
        ).sign(key)
        gen = MethodologyGenerator(caps)
        with pytest.raises(PermissionError, match="target mismatch"):
            gen.generate(
                GenerateRequest(
                    target="https://staging.example.com",
                    phase="exploit",
                    capabilities=["exploit_sqlmap"],
                    orchestrator=orch_instance,
                    approval_token=token,
                )
            )

    def test_exploit_refused_without_engagement(self, caps_path, orch):
        """Without a started engagement, exploit is refused."""
        from orchestrator.policy import Orchestrator
        from redteam.capabilities import load_capabilities
        from redteam.generator import GenerateRequest, MethodologyGenerator

        caps = load_capabilities(caps_path)
        orch_instance, key, eng = orch

        # Create a fresh orchestrator with no engagement started
        bare_orch = Orchestrator(key)

        gen = MethodologyGenerator(caps)
        with pytest.raises(PermissionError):
            gen.generate(
                GenerateRequest(
                    target="https://staging.example.com",
                    phase="exploit",
                    capabilities=["exploit_sqlmap"],
                    orchestrator=bare_orch,
                )
            )

    def test_post_exploit_also_refused_without_token(self, caps_path, orch):
        """Post-Exploit is also gated like Exploit."""
        from redteam.capabilities import load_capabilities
        from redteam.generator import GenerateRequest, MethodologyGenerator

        caps = load_capabilities(caps_path)
        orch_instance, key, eng = orch
        gen = MethodologyGenerator(caps)
        with pytest.raises(PermissionError, match="approval token"):
            gen.generate(
                GenerateRequest(
                    target="https://staging.example.com",
                    phase="post_exploit",
                    capabilities=["post_exploit_privesc"],
                    orchestrator=orch_instance,
                    approval_token=None,
                )
            )

    def test_refused_without_orchestrator(self, caps_path):
        """Fail closed: no orchestrator means no authorization, for any phase."""
        from redteam.capabilities import load_capabilities
        from redteam.generator import GenerateRequest, MethodologyGenerator

        caps = load_capabilities(caps_path)
        gen = MethodologyGenerator(caps)

        # Gated phase is refused with no orchestrator.
        with pytest.raises(PermissionError):
            gen.generate(
                GenerateRequest(
                    target="https://staging.example.com",
                    phase="exploit",
                    capabilities=["exploit_sqlmap"],
                    orchestrator=None,
                )
            )

        # Non-gated phase is also refused: recon/probe still need an engagement.
        with pytest.raises(PermissionError):
            gen.generate(
                GenerateRequest(
                    target="https://staging.example.com",
                    phase="probe",
                    capabilities=["web_sqli"],
                    orchestrator=None,
                )
            )


# ---------- Test checklist ----------


class TestChecklist:
    """Test pre-flight checklist generation."""

    def test_generate(self):
        from redteam.checklist import ChecklistGenerator

        c = ChecklistGenerator().generate(
            target="staging.example.com",
            phase="recon",
            engagement_id="ENG-001",
            authorized_by="tester",
        )
        assert "staging.example.com" in c.content
        assert "ENG-001" in c.content
        assert "tester" in c.content

    def test_checklist_has_scope_section(self):
        from redteam.checklist import ChecklistGenerator

        c = ChecklistGenerator().generate(target="example.com")
        assert "SCOPE" in c.content
        assert "TECHNICAL SAFEGUARDS" in c.content
        assert "OPERATOR DECLARATION" in c.content


# ---------- Test end-to-end workflow ----------


class TestEndToEnd:
    """Full workflow tests: recon -> probe -> exploit (gated)."""

    def test_workflow_recon_to_probe(self, caps_path, orch):
        """Recon -> Probe, both allowed with engagement."""
        from redteam.capabilities import load_capabilities
        from redteam.generator import GenerateRequest, MethodologyGenerator

        caps = load_capabilities(caps_path)
        orch_instance, key, eng = orch
        gen = MethodologyGenerator(caps)

        # Recon
        r1 = gen.generate(
            GenerateRequest(
                target="https://staging.example.com",
                phase="recon",
                capabilities=["recon_passive"],
                orchestrator=orch_instance,
            )
        )
        assert r1.content

        # Probe
        r2 = gen.generate(
            GenerateRequest(
                target="https://staging.example.com",
                phase="probe",
                capabilities=["web_sqli"],
                orchestrator=orch_instance,
            )
        )
        assert r2.content

    def test_workflow_exploit_refused(self, caps_path, orch):
        """Exploit without token fails in the full workflow."""
        from redteam.capabilities import load_capabilities
        from redteam.generator import GenerateRequest, MethodologyGenerator

        caps = load_capabilities(caps_path)
        orch_instance, key, eng = orch
        gen = MethodologyGenerator(caps)
        with pytest.raises(PermissionError):
            gen.generate(
                GenerateRequest(
                    target="https://staging.example.com",
                    phase="exploit",
                    capabilities=["exploit_sqlmap"],
                    orchestrator=orch_instance,
                )
            )

    def test_workflow_full_authorized(self, caps_path, orch):
        """Full authorized exploit after getting token."""
        from datetime import timedelta

        from orchestrator.engagement import ApprovalToken, now_utc
        from redteam.capabilities import load_capabilities
        from redteam.generator import GenerateRequest, MethodologyGenerator

        caps = load_capabilities(caps_path)
        orch_instance, key, eng = orch
        gen = MethodologyGenerator(caps)

        token = ApprovalToken(
            engagement_id=eng.id,
            action="exploit",
            target="https://staging.example.com",
            expires_at=(now_utc() + timedelta(hours=1)).isoformat(),
        ).sign(key)

        result = gen.generate(
            GenerateRequest(
                target="https://staging.example.com",
                phase="exploit",
                capabilities=["exploit_sqlmap"],
                orchestrator=orch_instance,
                approval_token=token,
            )
        )
        assert result.content
        assert "sqlmap" in result.content.lower()