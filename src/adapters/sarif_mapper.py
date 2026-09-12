"""Shared SARIF-to-WRAITH-finding mapping.

Extracted from the Strix adapter so any SARIF-emitting engine (Strix, and later
Trivy and Semgrep) maps results the same way, without importing StrixAdapter.
Layer inference, severity mapping, and the full WRAITH finding shape live here;
an adapter's _normalize is then just parse_sarif_results plus to_finding.

The finding shape matches schemas/finding.schema.json (additionalProperties is
false, so every key here is a declared property).
"""

from __future__ import annotations

import hashlib
import re

from .sarif import SarifResult

# The finding-id contract enforced by store.result_store (kept in sync here): a safe
# id has no path separators or colons, so it cannot escape the store directory. A
# fingerprint-less SARIF result falls back to "rule:file:line", which violates this,
# so an id that does not match is replaced by a stable hash of the fingerprint.
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _finding_id(engine: str, fingerprint: str) -> str:
    raw = f"{engine}-{fingerprint}"
    if _SAFE_ID.match(raw):
        return raw
    digest = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:32]
    return f"{engine}-{digest}"

# Keyword buckets (matched against rule id + message + tags) -> WRAITH layer.
_LAYER_KEYWORDS = [
    (7, ("prompt", "llm", "mcp", "agent", "memory", "rag", "tool-poison", "tool poison")),
    (5, ("aws", "azure", "gcp", "s3", "iam", "kubernetes", "k8s", "cloud")),
    (4, ("port", "ssh", "smtp", "smb", "kerberos", "ldap", "dns", "network")),
    (3, ("graphql", "jwt", "oauth", "bola", "api")),
    (2, ("xss", "sqli", "sql injection", "ssrf", "csrf", "idor", "web", "xxe")),
]


def severity(level: str, security_severity: float | None) -> str:
    """Map a SARIF level and optional security-severity (0..10) to WRAITH severity."""
    if security_severity is not None:
        if security_severity >= 9.0:
            return "CRITICAL"
        if security_severity >= 7.0:
            return "HIGH"
        if security_severity >= 4.0:
            return "MEDIUM"
        if security_severity > 0:
            return "LOW"
    return {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}.get(level.lower(), "INFORMATIONAL")


def layer_for(result: SarifResult, default_layer: int) -> int:
    """Infer the WRAITH layer from the rule id, message, and tags; else default."""
    haystack = " ".join([result.rule_id, result.message, *result.tags]).lower()
    for layer, keywords in _LAYER_KEYWORDS:
        if any(k in haystack for k in keywords):
            return layer
    return default_layer


def to_finding(result: SarifResult, engine: str, default_layer: int) -> dict:
    """Convert one SarifResult into a WRAITH-normalized finding dict."""
    fingerprint = result.fingerprint or f"{result.rule_id}:{result.file}:{result.start_line}"
    return {
        "finding_id": _finding_id(engine, fingerprint),
        "fingerprint": fingerprint,
        "rule_id": result.rule_id,
        "engine": engine,
        "layer": layer_for(result, default_layer),
        "title": result.message or result.rule_id,
        "description": result.message or None,
        "rule_lifecycle": "ACTIVE",
        "implementation_capability": "IMPLEMENTED",
        "evaluation_result": "FINDING",
        "severity": severity(result.level, result.security_severity),
        "confidence": "MEDIUM",  # SARIF has no standard confidence field
        "location": {
            "target": result.file,
            "file": result.file,
            "start_line": result.start_line,
            "end_line": result.end_line,
        },
        "policy_evidence": {"state": "UNKNOWN", "reason": f"not assessed by {engine}"},
        "remediation": {},
        "coverage_status": "INTEGRATED",
    }
