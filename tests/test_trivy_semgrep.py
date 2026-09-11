"""Trivy and Semgrep adapter tests (no engine install needed).

Both are SARIF-on-stdout CLI engines sharing SarifCliAdapter; a canned runner feeds
SARIF so normalization is tested without the binary present.
"""

from __future__ import annotations

import json

from adapters import AdapterRequest, SemgrepAdapter, SubprocessResult, TrivyAdapter

_REQUIRED = {"finding_id", "fingerprint", "rule_id", "layer", "severity", "confidence", "evaluation_result"}

SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "t", "rules": [
                {"id": "CVE-2024-1", "properties": {"tags": ["vuln"], "security-severity": "8.1"}},
            ]}},
            "results": [
                {
                    "ruleId": "CVE-2024-1", "ruleIndex": 0, "level": "error",
                    "message": {"text": "vulnerable dependency"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "requirements.txt"},
                        "region": {"startLine": 3}}}],
                    "partialFingerprints": {"h": "fp-cve"},
                },
            ],
        }
    ],
}


def _runner(text):
    def run(_request):
        return SubprocessResult(returncode=0, stdout=text, stderr="")
    return run


def _adapter(cls, tmp_path):
    return cls(engine_path=tmp_path, command_prefix=["echo"])


def test_trivy_normalizes_sarif(tmp_path):
    result = _adapter(TrivyAdapter, tmp_path).run(
        AdapterRequest(target="./repo"), runner=_runner(json.dumps(SARIF))
    )
    assert result.status == "OK" and len(result.findings) == 1
    f = result.findings[0]
    assert _REQUIRED <= set(f)
    assert f["engine"] == "trivy" and f["finding_id"] == "trivy-fp-cve"
    assert f["severity"] == "HIGH" and f["layer"] == 6  # security-severity 8.1


def test_semgrep_normalizes_sarif(tmp_path):
    result = _adapter(SemgrepAdapter, tmp_path).run(
        AdapterRequest(target="./repo"), runner=_runner(json.dumps(SARIF))
    )
    f = result.findings[0]
    assert f["engine"] == "semgrep" and f["finding_id"] == "semgrep-fp-cve"
    assert _REQUIRED <= set(f)


def test_unavailable_without_binary(tmp_path):
    # No command_prefix; the binary is (almost certainly) not on PATH in CI.
    adapter = TrivyAdapter(engine_path=tmp_path)
    ok, _ = adapter.is_available()
    result = adapter.run(AdapterRequest(target="./repo"), runner=_runner(json.dumps(SARIF)))
    assert result.status in ("OK", "UNAVAILABLE")
    if not ok:
        assert result.status == "UNAVAILABLE" and result.coverage["status"] == "NOT_EVALUATED"


def test_bad_output_is_error(tmp_path):
    result = _adapter(SemgrepAdapter, tmp_path).run(
        AdapterRequest(target="./repo"), runner=_runner("not json")
    )
    assert result.status == "ERROR"


def test_trivy_argv_fs_and_image(tmp_path):
    a = _adapter(TrivyAdapter, tmp_path)
    fs = a._argv(["trivy"], AdapterRequest(target="./repo"))
    assert fs[:2] == ["trivy", "fs"] and "sarif" in fs and fs[-1] == "./repo" and "--scanners" in fs
    img = a._argv(["trivy"], AdapterRequest(target="img:tag", options={"scan": "image"}))
    assert img[:2] == ["trivy", "image"] and "--scanners" not in img


def test_semgrep_argv_config(tmp_path):
    a = _adapter(SemgrepAdapter, tmp_path)
    argv = a._argv(["semgrep"], AdapterRequest(target="./repo"))
    assert argv[:2] == ["semgrep", "scan"] and "--sarif" in argv and "auto" in argv
    custom = a._argv(["semgrep"], AdapterRequest(target="./repo", options={"config": "p/ci"}))
    assert "p/ci" in custom


def test_cli_lists_new_engines(capsys):
    from cli import wraith
    assert wraith.main(["engine", "list"]) == 0
    out = capsys.readouterr().out
    assert "trivy" in out and "semgrep" in out


def test_track_selection_static_and_all():
    from cli.wraith import _adapters_for
    # Explicit sast track selects the static engines regardless of target kind.
    assert {"trivy", "semgrep", "skillspector"} <= set(_adapters_for("sast", "./repo"))
    # --track all on a repo path includes the static engines, not the dynamic ones.
    all_static = _adapters_for("all", "./repo")
    assert {"trivy", "semgrep", "skillspector"} <= set(all_static) and "strix" not in all_static
    # --track all on a live host includes only dynamic engines.
    all_dynamic = _adapters_for("all", "https://example.com")
    assert "strix" in all_dynamic and "trivy" not in all_dynamic and "semgrep" not in all_dynamic
