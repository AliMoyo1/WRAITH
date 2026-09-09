"""Tests for the entitlement layer: signed grants, the role-by-tier matrix, and
the fail-closed verifier."""

from __future__ import annotations

from datetime import timedelta

import pytest

from entitlement import (
    CapabilityClass,
    CapabilityGrant,
    EntitlementError,
    Role,
    Tier,
    capabilities_for,
    now_utc,
    require_entitlement,
)

KEY = b"entitlement-test-key"


def _grant(
    capabilities: list[str],
    key: bytes = KEY,
    tenant: str = "t1",
    principal: str = "p1",
    roles: list[str] | None = None,
    tier: str = "enterprise",
    hours: float = 1.0,
) -> CapabilityGrant:
    return CapabilityGrant(
        tenant_id=tenant,
        principal_id=principal,
        roles=roles or ["operator"],
        tier=tier,
        capabilities=capabilities,
        issued_at=now_utc().isoformat(),
        expires_at=(now_utc() + timedelta(hours=hours)).isoformat(),
    ).sign(key)


class TestGrant:
    def test_sign_verify_roundtrip(self):
        assert _grant(["control_plane_read"]).verify(KEY) is True

    def test_wrong_key_fails(self):
        assert _grant(["control_plane_read"]).verify(b"other-key") is False

    def test_tamper_detected(self):
        g = _grant(["control_plane_read"])
        g.capabilities.append("redteam_exploit")  # escalate after signing
        assert g.verify(KEY) is False

    def test_signature_is_order_independent(self):
        g = _grant(["redteam_probe", "control_plane_read"])
        assert g.verify(KEY) is True
        # A serialize/deserialize round trip still verifies.
        assert CapabilityGrant.from_dict(g.to_dict()).verify(KEY) is True

    def test_expiry(self):
        assert _grant(["control_plane_read"], hours=-1.0).is_expired() is True

    def test_to_from_dict_roundtrip(self):
        g = _grant(["control_plane_read", "control_plane_scan"])
        g2 = CapabilityGrant.from_dict(g.to_dict())
        assert g2.tenant_id == g.tenant_id
        assert g2.nonce == g.nonce
        assert g2.signature == g.signature
        assert g2.verify(KEY) is True

    def test_allows(self):
        g = _grant(["control_plane_read"])
        assert g.allows("control_plane_read") is True
        assert g.allows("redteam_exploit") is False


class TestMatrix:
    def test_community_viewer_read_only(self):
        assert capabilities_for([Role.VIEWER], Tier.COMMUNITY) == ["control_plane_read"]

    def test_community_analyst_gets_scan_not_recon(self):
        caps = capabilities_for(["analyst"], "community")  # string inputs accepted
        assert "control_plane_scan" in caps
        assert "redteam_recon" not in caps  # recon needs Pro

    def test_pro_analyst_gets_recon_and_probe(self):
        caps = capabilities_for([Role.ANALYST], Tier.PRO)
        assert "redteam_recon" in caps and "redteam_probe" in caps
        assert "redteam_exploit" not in caps  # exploit needs Enterprise + Operator

    def test_enterprise_operator_gets_exploit(self):
        caps = capabilities_for([Role.OPERATOR], Tier.ENTERPRISE)
        assert "redteam_exploit" in caps and "redteam_post_exploit" in caps

    def test_separation_of_duties_admin_is_not_operator(self):
        caps = capabilities_for([Role.ADMIN], Tier.ENTERPRISE)
        assert "admin" in caps
        assert "control_plane_read" in caps
        assert "redteam_exploit" not in caps  # Operator only
        assert "control_plane_scan" not in caps  # Analyst/Operator only

    def test_multiple_roles_take_the_union(self):
        caps = capabilities_for([Role.ADMIN, Role.OPERATOR], Tier.ENTERPRISE)
        assert "admin" in caps and "redteam_exploit" in caps


class TestRequireEntitlement:
    def test_allows_included_class(self):
        require_entitlement(_grant(["redteam_exploit"]), CapabilityClass.REDTEAM_EXPLOIT, KEY)

    def test_denies_missing_class(self):
        with pytest.raises(EntitlementError, match="does not include"):
            require_entitlement(_grant(["redteam_probe"]), CapabilityClass.REDTEAM_EXPLOIT, KEY)

    def test_none_grant_denied(self):
        with pytest.raises(EntitlementError, match="no grant"):
            require_entitlement(None, CapabilityClass.CONTROL_PLANE_READ, KEY)

    def test_bad_signature_denied(self):
        with pytest.raises(EntitlementError, match="signature"):
            require_entitlement(_grant(["redteam_exploit"]), CapabilityClass.REDTEAM_EXPLOIT, b"wrong")

    def test_expired_denied(self):
        with pytest.raises(EntitlementError, match="expired"):
            require_entitlement(
                _grant(["redteam_exploit"], hours=-1.0), CapabilityClass.REDTEAM_EXPLOIT, KEY
            )

    def test_accepts_string_class(self):
        require_entitlement(_grant(["control_plane_read"]), "control_plane_read", KEY)


class TestConfigIntegration:
    def test_entitlement_key_requires_env(self, monkeypatch):
        import config

        monkeypatch.delenv("WRAITH_ENTITLEMENT_KEY", raising=False)
        with pytest.raises(RuntimeError):
            config.entitlement_key()

    def test_entitlement_key_reads_env(self, monkeypatch):
        import config

        monkeypatch.setenv("WRAITH_ENTITLEMENT_KEY", "k")
        assert config.entitlement_key() == b"k"

    def test_grant_save_load_roundtrip(self, tmp_path):
        import config

        g = _grant(["control_plane_read"])
        path = tmp_path / "grant.json"
        config.save_grant(path, g)
        loaded = config.load_grant(path)
        assert loaded.verify(KEY) is True
        assert loaded.capabilities == g.capabilities
