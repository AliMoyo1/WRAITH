"""Strix adapter + SARIF parser tests (no Strix install needed)."""

from __future__ import annotations

import json

from adapters import AdapterRequest, StrixAdapter, SubprocessResult
from adapters.sarif import parse_sarif_results

SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "Strix", "rules": [
                {"id": "SQLI", "properties": {"tags": ["security"], "security-severity": "9.8"}},
                {"id": "llm-prompt-injection", "properties": {"tags": ["agentic"]}},
                {"id": "aws-s3-public", "properties": {"tags": ["cloud"]}},
            ]}},
            "results": [
                {
                    "ruleId": "SQLI", "ruleIndex": 0, "level": "error",
                    "message": {"text": "SQL injection in login"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "app/login.py"},
                        "region": {"startLine": 42, "endLine": 45}}}],
                    "partialFingerprints": {"h": "fp-sqli"},
                },
                {"ruleId": "llm-prompt-injection", "ruleIndex": 1, "level": "warning",
                 "message": {"text": "Prompt injection via tool output"}},
                {"ruleId": "aws-s3-public", "ruleIndex": 2, "level": "note",
                 "message": {"text": "Public S3 bucket"}},
            ],
        }
    ],
}

_REQUIRED = {"finding_id", "fingerprint", "rule_id", "layer", "severity", "confidence", "evaluation_result"}


def _adapter(tmp_path):
    return StrixAdapter(engine_path=tmp_path, command_prefix=["echo"])


def _runner(text):
    def run(_request):
        return SubprocessResult(returncode=0, stdout=text, stderr="")
    return run


def test_sarif_parser_extracts_fields():
    results = parse_sarif_results(json.dumps(SARIF))
    assert len(results) == 3
    sqli = results[0]
    assert sqli.rule_id == "SQLI" and sqli.level == "error"
    assert sqli.file == "app/login.py" and sqli.start_line == 42 and sqli.end_line == 45
    assert sqli.fingerprint == "fp-sqli" and sqli.security_severity == 9.8


def test_strix_normalization_and_severity(tmp_path):
    result = _adapter(tmp_path).run(AdapterRequest(target="https://x.test"), runner=_runner(json.dumps(SARIF)))
    assert result.status == "OK" and len(result.findings) == 3
    by_rule = {f["rule_id"]: f for f in result.findings}
    assert by_rule["SQLI"]["severity"] == "CRITICAL"      # security-severity 9.8
    assert by_rule["SQLI"]["engine"] == "strix" and by_rule["SQLI"]["fingerprint"] == "fp-sqli"
    assert by_rule["llm-prompt-injection"]["severity"] == "MEDIUM"  # warning, no security-severity
    assert by_rule["aws-s3-public"]["severity"] == "LOW"           # note
    for f in result.findings:
        assert _REQUIRED <= set(f)
        assert f["evaluation_result"] == "FINDING"


def test_strix_layer_classification(tmp_path):
    result = _adapter(tmp_path).run(AdapterRequest(target="x"), runner=_runner(json.dumps(SARIF)))
    by_rule = {f["rule_id"]: f for f in result.findings}
    assert by_rule["SQLI"]["layer"] == 2                  # web
    assert by_rule["llm-prompt-injection"]["layer"] == 7  # agentic
    assert by_rule["aws-s3-public"]["layer"] == 5         # cloud


def test_strix_empty_sarif_is_ok(tmp_path):
    empty = _runner(json.dumps({"version": "2.1.0", "runs": []}))
    result = _adapter(tmp_path).run(AdapterRequest(target="x"), runner=empty)
    assert result.status == "OK" and result.findings == []


def test_strix_bad_output_is_error(tmp_path):
    result = _adapter(tmp_path).run(AdapterRequest(target="x"), runner=_runner("not json"))
    assert result.status == "ERROR"


def test_strix_unavailable_is_not_evaluated(tmp_path):
    adapter = StrixAdapter(engine_path=tmp_path / "absent", command_prefix=["echo"])
    result = adapter.run(AdapterRequest(target="x"), runner=_runner(json.dumps(SARIF)))
    assert result.status == "UNAVAILABLE" and result.coverage["status"] == "NOT_EVALUATED"


def test_cli_lists_and_checks_strix():
    from cli import wraith
    assert wraith.main(["engine", "list"]) == 0
    # repos/strix is absent in the working tree, so check reports unavailable.
    assert wraith.main(["engine", "check", "strix"]) == 1
