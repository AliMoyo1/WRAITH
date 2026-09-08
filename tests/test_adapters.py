"""Engine-adapter tests: SkillSpector normalization and the run contract."""

from __future__ import annotations

import json

from adapters import AdapterRequest, SkillSpectorAdapter, SubprocessResult

CANNED = {
    "findings": [
        {
            "finding_id": "finding-abc", "rule_id": "PE3", "message": "Credential access",
            "severity": "HIGH", "confidence": 0.9, "file": "skill.py", "start_line": 10,
            "end_line": 12, "category": "Privilege Escalation", "remediation": "scope down",
            "match_fingerprint": "fp1",
        },
        {
            "finding_id": "finding-def", "rule_id": "P1", "message": "Instruction override",
            "severity": "INFO", "confidence": 0.4, "file": "SKILL.md", "start_line": 1,
            "category": "Prompt Injection",
        },
    ]
}

_REQUIRED = {"finding_id", "fingerprint", "rule_id", "layer", "severity", "confidence", "evaluation_result"}
_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}
_RESULTS = {"FINDING", "NO_FINDING", "REVIEW_REQUIRED", "NOT_EVALUATED", "ERROR"}


def _valid_finding(f: dict) -> None:
    assert _REQUIRED <= set(f)
    assert f["severity"] in _SEVERITIES
    assert f["confidence"] in {"HIGH", "MEDIUM", "LOW"}
    assert f["evaluation_result"] in _RESULTS
    assert 0 <= f["layer"] <= 12


def _adapter(tmp_path):
    # A real, existing engine path plus an injected command prefix makes the
    # adapter "available" without SkillSpector actually being installed.
    return SkillSpectorAdapter(engine_path=tmp_path, command_prefix=["echo"])


def _ok_runner(_request):
    return SubprocessResult(returncode=0, stdout=json.dumps(CANNED), stderr="")


def test_normalization_maps_fields_and_layers(tmp_path):
    result = _adapter(tmp_path).run(AdapterRequest(target="repo"), runner=_ok_runner)
    assert result.status == "OK"
    assert len(result.findings) == 2
    a, b = result.findings
    assert a["rule_id"] == "PE3" and a["layer"] == 6 and a["severity"] == "HIGH" and a["confidence"] == "HIGH"
    assert a["fingerprint"] == "fp1" and a["evaluation_result"] == "FINDING"
    assert b["layer"] == 7 and b["severity"] == "INFORMATIONAL" and b["confidence"] == "LOW"
    for f in result.findings:
        _valid_finding(f)


def test_real_category_values_map_to_layers(tmp_path):
    # Regression guard for the StrEnum value form ("Prompt Injection", not
    # "prompt_injection"). With the old snake_case set every finding wrongly
    # landed in layer 6.
    cats = {
        "Prompt Injection": 7, "Anti-Refusal": 7, "MCP Tool Poisoning": 7,
        "Excessive Agency": 7, "Memory Poisoning": 7, "Agent Snooping": 7,
        "Output Handling": 7,
        "Data Exfiltration": 6, "Insecure Deserialization": 6,
        "Server-Side Request Forgery": 6, "Supply Chain": 6, "YARA Match": 6,
    }
    findings = [
        {"finding_id": f"f{i}", "rule_id": "X", "severity": "LOW", "confidence": 0.5, "category": c}
        for i, c in enumerate(cats)
    ]

    def runner(_request):
        return SubprocessResult(returncode=0, stdout=json.dumps({"findings": findings}), stderr="")

    result = _adapter(tmp_path).run(AdapterRequest(target="repo"), runner=runner)
    for i, (category, expected) in enumerate(cats.items()):
        assert result.findings[i]["layer"] == expected, f"{category} -> {result.findings[i]['layer']}"


def test_unavailable_engine_is_not_evaluated(tmp_path):
    adapter = SkillSpectorAdapter(engine_path=tmp_path / "does-not-exist", command_prefix=["echo"])
    result = adapter.run(AdapterRequest(target="repo"), runner=_ok_runner)
    assert result.status == "UNAVAILABLE"
    assert result.findings == []
    assert result.coverage["status"] == "NOT_EVALUATED"


def test_timeout_reported(tmp_path):
    def timeout_runner(_request):
        return SubprocessResult(returncode=-1, stdout="", stderr="", timed_out=True)
    result = _adapter(tmp_path).run(AdapterRequest(target="repo"), runner=timeout_runner)
    assert result.status == "TIMEOUT"
    assert result.coverage["status"] == "INCOMPLETE"


def test_engine_error_reported(tmp_path):
    def error_runner(_request):
        return SubprocessResult(returncode=2, stdout="", stderr="boom")
    result = _adapter(tmp_path).run(AdapterRequest(target="repo"), runner=error_runner)
    assert result.status == "ERROR"
    assert "boom" in result.errors[0]


def test_unparseable_output_is_error(tmp_path):
    def junk_runner(_request):
        return SubprocessResult(returncode=0, stdout="not json", stderr="")
    result = _adapter(tmp_path).run(AdapterRequest(target="repo"), runner=junk_runner)
    assert result.status == "ERROR"
    assert "parse" in result.errors[0].lower()


def test_batch_skills_shape_supported(tmp_path):
    batch = {"skills": [{"findings": [CANNED["findings"][0]]}, {"findings": [CANNED["findings"][1]]}]}

    def batch_runner(_request):
        return SubprocessResult(returncode=0, stdout=json.dumps(batch), stderr="")
    result = _adapter(tmp_path).run(AdapterRequest(target="repo"), runner=batch_runner)
    assert result.status == "OK" and len(result.findings) == 2


def test_no_llm_default(tmp_path):
    assert AdapterRequest(target="x").no_llm is True


def test_cli_engine_list(capsys):
    from cli import wraith
    assert wraith.main(["engine", "list"]) == 0
    assert "skillspector" in capsys.readouterr().out


def test_cli_engine_check_unavailable_when_engine_absent():
    # repos/SkillSpector is not present in the working tree, so check reports
    # unavailable (exit 1) rather than pretending the engine is there.
    from cli import wraith
    assert wraith.main(["engine", "check", "skillspector"]) == 1


def test_cli_engine_run_unavailable_returns_0():
    from cli import wraith
    # UNAVAILABLE is a clean outcome (NOT_EVALUATED), not a failure.
    assert wraith.main(["engine", "run", "skillspector", "some-target"]) == 0


def test_cli_engine_unknown_returns_2():
    from cli import wraith
    assert wraith.main(["engine", "check", "nope"]) == 2


def test_adapter_findings_persist_to_store(tmp_path):
    from store import ResultStore
    result = _adapter(tmp_path).run(AdapterRequest(target="repo"), runner=_ok_runner)
    store = ResultStore(tmp_path / "results", "eng-1", b"master-key", actor="engine:skillspector")
    ids = [store.put_finding(f) for f in result.findings]
    assert len(ids) == 2
    got = store.get_finding(ids[0])
    assert got["engine"] == "skillspector" and got["evaluation_result"] == "FINDING"
    assert store.verify_audit() is True
