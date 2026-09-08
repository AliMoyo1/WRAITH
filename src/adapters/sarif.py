"""Minimal, robust SARIF 2.1.0 result parser.

Reusable by any adapter whose engine emits SARIF (Strix does, via a
findings.sarif sidecar). Returns engine-neutral results; the adapter maps them
to WRAITH-normalized findings (adding engine, layer, evaluation_result, etc.).

Only the fields WRAITH needs are read, and everything is defensive: a malformed
or partial SARIF document yields the results it can, not an exception.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SarifResult:
    rule_id: str
    level: str  # SARIF: error | warning | note | none
    message: str
    file: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    fingerprint: str | None = None
    security_severity: float | None = None  # SARIF property, a CVSS-like 0..10
    tags: list[str] = field(default_factory=list)


def _rules_index(driver: dict) -> dict:
    """Map rule id -> rule object and index -> rule object."""
    by_key: dict = {}
    for i, rule in enumerate(driver.get("rules", []) or []):
        if isinstance(rule, dict):
            by_key[i] = rule
            rid = rule.get("id")
            if rid:
                by_key[rid] = rule
    return by_key


def _first_location(result: dict) -> tuple[str | None, int | None, int | None]:
    for loc in result.get("locations", []) or []:
        phys = (loc or {}).get("physicalLocation") or {}
        uri = ((phys.get("artifactLocation") or {}).get("uri"))
        region = phys.get("region") or {}
        start = region.get("startLine")
        end = region.get("endLine")
        if uri or start:
            return uri, start, end
    return None, None, None


def _fingerprint(result: dict) -> str | None:
    for key in ("fingerprints", "partialFingerprints"):
        fp = result.get(key)
        if isinstance(fp, dict) and fp:
            # Deterministic: first value by sorted key.
            first = sorted(fp.items())[0]
            return str(first[1])
    return None


def _security_severity(props: dict) -> float | None:
    raw = props.get("security-severity")
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def parse_sarif_results(text: str) -> list[SarifResult]:
    import json

    data = json.loads(text)
    out: list[SarifResult] = []
    for run in data.get("runs", []) or []:
        driver = ((run.get("tool") or {}).get("driver")) or {}
        rules = _rules_index(driver)
        for result in run.get("results", []) or []:
            if not isinstance(result, dict):
                continue
            rule = {}
            if result.get("ruleIndex") in rules:
                rule = rules[result["ruleIndex"]]
            elif result.get("ruleId") in rules:
                rule = rules[result["ruleId"]]
            rule_id = result.get("ruleId") or rule.get("id") or "UNKNOWN"
            level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
            message = ((result.get("message") or {}).get("text")) or ""
            file, start, end = _first_location(result)
            props = rule.get("properties") or {}
            tags = [str(t) for t in (props.get("tags") or [])]
            out.append(
                SarifResult(
                    rule_id=str(rule_id),
                    level=str(level),
                    message=message,
                    file=file,
                    start_line=start,
                    end_line=end,
                    fingerprint=_fingerprint(result),
                    security_severity=_security_severity(props),
                    tags=tags,
                )
            )
    return out
