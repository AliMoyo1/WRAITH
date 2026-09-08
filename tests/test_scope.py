"""Scope matching tests, including the specific bypasses the audit found."""

from __future__ import annotations

from orchestrator.scope import Scope, ScopeList, classify_target


def _scope(**allow) -> Scope:
    return Scope(allow=ScopeList(**allow), enabled=True)


def test_disabled_scope_denies_everything():
    s = Scope(allow=ScopeList(domains=["example.com"]), enabled=False)
    assert s.allows("example.com") is False


def test_domain_exact_and_subdomain_match():
    s = _scope(domains=["example.com"])
    assert s.allows("example.com") is True
    assert s.allows("api.example.com") is True


def test_domain_rejects_suffix_impersonation():
    # The audit case: example.com.attacker.test must NOT match example.com.
    s = _scope(domains=["example.com"])
    assert s.allows("example.com.attacker.test") is False
    assert s.allows("notexample.com") is False


def test_empty_entries_never_match():
    s = _scope(domains=[""], cidrs=["  "], urls=[""], repo_paths=[""])
    assert s.allows("anything.test") is False
    assert s.allows("10.0.0.1") is False


def test_cidr_contains_and_excludes():
    s = _scope(cidrs=["10.0.0.0/24"])
    assert s.allows("10.0.0.7") is True   # audit case: valid IP in CIDR must pass
    assert s.allows("10.0.1.7") is False
    assert s.allows("192.168.0.1") is False


def test_url_path_boundary():
    s = _scope(urls=["https://example.com/app"])
    assert s.allows("https://example.com/app") is True
    assert s.allows("https://example.com/app/login") is True
    assert s.allows("https://example.com/apple") is False   # boundary, not prefix
    assert s.allows("http://example.com/app") is False       # scheme must match


def test_url_authorized_by_domain_entry():
    s = _scope(domains=["example.com"])
    assert s.allows("https://api.example.com/x") is True
    assert s.allows("https://example.com.evil.test/x") is False


def test_repo_path_containment(tmp_path):
    root = tmp_path / "repo"
    inside = root / "project"
    inside.mkdir(parents=True)
    evil = tmp_path / "repo-evil"
    evil.mkdir()
    s = _scope(repo_paths=[str(root)])
    assert s.allows(str(inside)) is True
    assert s.allows(str(evil)) is False   # audit case: C:/repository-evil style


def test_blocklist_wins():
    s = Scope(
        allow=ScopeList(cidrs=["10.0.0.0/8"]),
        block=ScopeList(cidrs=["10.0.0.0/24"]),
        enabled=True,
    )
    assert s.allows("10.1.0.5") is True
    assert s.allows("10.0.0.5") is False   # blocked subnet wins over broad allow


def test_guard_url_blocks_metadata():
    s = _scope(domains=["example.com"])
    ok, reason = s.guard_url("http://169.254.169.254/latest/meta-data/")
    assert ok is False and "metadata" in reason


def test_classify_target():
    assert classify_target("https://x.test/a") == "url"
    assert classify_target("10.0.0.0/24") == "cidr"
    assert classify_target("10.0.0.5") == "cidr"
    assert classify_target("C:/repo/project") == "repo_path"
    assert classify_target("/home/user/repo") == "repo_path"
    assert classify_target("example.com") == "domain"
