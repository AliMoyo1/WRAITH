"""Tests for the shared SARIF mapping (adapters.sarif_mapper).

These lock the behavior extracted from the Strix adapter so Trivy and Semgrep can
reuse it. The Strix adapter's own tests (tests/test_strix.py) continue to exercise
the same functions through StrixAdapter, unchanged.
"""

from __future__ import annotations

from adapters.sarif import SarifResult
from adapters.sarif_mapper import layer_for, severity, to_finding

_REQUIRED = {"finding_id", "fingerprint", "rule_id", "layer", "severity", "confidence", "evaluation_result"}


def _result(rule_id="R", level="warning", message="", tags=(), sec=None, fp="fp", file="f.py", line=1):
    return SarifResult(
        rule_id=rule_id, level=level, message=message, file=file,
        start_line=line, end_line=line, fingerprint=fp,
        security_severity=sec, tags=list(tags),
    )


def test_severity_from_security_severity():
    assert severity("note", 9.8) == "CRITICAL"
    assert severity("note", 7.0) == "HIGH"
    assert severity("note", 4.0) == "MEDIUM"
    assert severity("note", 0.5) == "LOW"


def test_severity_from_level_when_no_score():
    assert severity("error", None) == "HIGH"
    assert severity("warning", None) == "MEDIUM"
    assert severity("note", None) == "LOW"
    assert severity("none", None) == "INFORMATIONAL"


def test_layer_for_keyword_buckets():
    assert layer_for(_result(rule_id="sqli-check", message="SQL injection"), 6) == 2
    assert layer_for(_result(rule_id="llm-prompt", tags=["agent"]), 6) == 7
    assert layer_for(_result(rule_id="aws-s3", message="public bucket"), 6) == 5
    assert layer_for(_result(rule_id="unknown", message="misc"), 6) == 6  # falls back to default


def test_to_finding_is_reusable_and_complete():
    f = to_finding(_result(rule_id="dep-CVE-1", message="vuln", sec=7.5, fp="abc"), "trivy", 6)
    assert _REQUIRED <= set(f)
    assert f["finding_id"] == "trivy-abc" and f["engine"] == "trivy"
    assert f["severity"] == "HIGH" and f["layer"] == 6
    assert f["evaluation_result"] == "FINDING" and f["coverage_status"] == "INTEGRATED"


def test_finding_id_is_safe_when_no_fingerprint(tmp_path):
    from store import ResultStore

    # No SARIF fingerprint: the fallback "rule:file:line" has a colon and a path
    # separator, which the result store rejects. The finding id must still be safe.
    f = to_finding(_result(rule_id="R", fp=None, file="src/a.py", line=1), "semgrep", 6)
    assert f["fingerprint"] == "R:src/a.py:1"  # human-readable fingerprint preserved
    assert ":" not in f["finding_id"] and "/" not in f["finding_id"]
    assert f["finding_id"].startswith("semgrep-")
    # And it actually persists: previously this raised ResultStoreError and failed the scan.
    store = ResultStore(tmp_path, "scan-1", b"master-key-bytes", actor="test")
    assert store.put_finding(f) == f["finding_id"]


def test_finding_id_preserved_when_fingerprint_is_safe():
    f = to_finding(_result(rule_id="R", fp="fp-1"), "trivy", 6)
    assert f["finding_id"] == "trivy-fp-1"  # a readable, already-safe id is kept as-is
