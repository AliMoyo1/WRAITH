"""SkillSpector engine adapter.

Runs `skillspector scan <target> --format json [--no-llm]` as an isolated
subprocess and normalizes its findings to the WRAITH finding schema.

Grounded in the real SkillSpector interface (NVIDIA/SkillSpector):
  * CLI entry point `skillspector` (skillspector.cli:app), `scan` command with
    `--format json`, `--output`, and `--no-llm`.
  * `--format json` emits a top-level object with a "findings" list.
  * Each finding carries: rule_id, message, finding_id, severity, confidence
    (0..1 float), file, start_line, end_line, category, remediation,
    match_fingerprint, code_snippet.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .base import AdapterRequest, EngineAdapter, SubprocessResult, run_subprocess, scrubbed_env

# SkillSpector categories that belong to the agentic layer (7); everything else is SAST (6).
_AGENTIC_CATEGORIES = {
    "prompt_injection", "anti_refusal", "excessive_agency", "memory_poisoning",
    "tool_misuse", "mcp_tool_poisoning", "mcp_least_privilege", "mcp_rug_pull",
    "rogue_agent", "system_prompt_leakage", "agent_snooping", "output_handling",
}
_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
    "LOW": "LOW", "INFO": "INFORMATIONAL", "INFORMATIONAL": "INFORMATIONAL",
}


def _confidence_bucket(value: object) -> str:
    if not isinstance(value, (int, float, str)):
        return "MEDIUM"
    try:
        c = float(value)  # SkillSpector confidence is a 0..1 float
    except (TypeError, ValueError):
        return "MEDIUM"
    if c >= 0.8:
        return "HIGH"
    if c >= 0.5:
        return "MEDIUM"
    return "LOW"


class SkillSpectorAdapter(EngineAdapter):
    name = "skillspector"

    def __init__(
        self,
        engine_path: str | Path,
        command_prefix: list[str] | None = None,
        pinned_commit: str | None = None,
    ):
        self.engine_path = Path(engine_path)
        self._command_prefix = command_prefix
        self.pinned_commit = pinned_commit

    # ---- availability ----------------------------------------------------
    def _resolve_command(self) -> list[str] | None:
        if self._command_prefix:
            return list(self._command_prefix)
        for rel in ("Scripts/python.exe", "bin/python"):
            venv_py = self.engine_path / ".venvs" / "skillspector" / rel
            if venv_py.exists():
                return [str(venv_py), "-m", "skillspector"]
        found = shutil.which("skillspector")
        if found:
            return [found]
        return [sys.executable, "-m", "skillspector"]

    def is_available(self) -> tuple[bool, str]:
        if not self.engine_path.exists():
            return False, f"engine path not found: {self.engine_path}"
        cmd = self._resolve_command()
        if cmd is None:
            return False, "no runnable skillspector command resolved"
        if self.pinned_commit:
            head = self.engine_version()
            if head and not self.pinned_commit.startswith(head) and not head.startswith(self.pinned_commit):
                return False, f"engine commit {head} does not match pinned {self.pinned_commit}"
        return True, "available"

    def engine_version(self) -> str | None:
        try:
            out = subprocess.run(
                ["git", "-C", str(self.engine_path), "rev-parse", "HEAD"],
                capture_output=True, text=True, timeout=10, check=False, env=scrubbed_env(),
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return out.stdout.strip() or None

    # ---- execution -------------------------------------------------------
    def _default_runner(self, request: AdapterRequest) -> SubprocessResult:
        cmd = self._resolve_command()
        assert cmd is not None  # guarded by is_available before run()
        workdir = tempfile.mkdtemp(prefix="wraith-skillspector-")
        out_file = Path(workdir) / "report.json"
        full = [*cmd, "scan", request.target, "--format", "json", "--output", str(out_file)]
        if request.no_llm:
            full.append("--no-llm")
        result = run_subprocess(full, cwd=self.engine_path, timeout=request.timeout_seconds)
        # Prefer the JSON file; fall back to stdout.
        if out_file.exists():
            try:
                result = SubprocessResult(
                    returncode=result.returncode,
                    stdout=out_file.read_text(encoding="utf-8"),
                    stderr=result.stderr,
                    timed_out=result.timed_out,
                )
            except OSError:
                pass
        return result

    # ---- normalization ---------------------------------------------------
    def _normalize(self, raw_output: str) -> list[dict]:
        data = json.loads(raw_output)
        raw_findings = self._extract_findings(data)
        return [self._map_finding(f) for f in raw_findings]

    @staticmethod
    def _extract_findings(data: dict) -> list[dict]:
        if isinstance(data.get("findings"), list):
            return data["findings"]
        # Batch scans nest findings under a "skills" array.
        out: list[dict] = []
        for skill in data.get("skills", []) or []:
            if isinstance(skill, dict) and isinstance(skill.get("findings"), list):
                out.extend(skill["findings"])
        return out

    def _map_finding(self, f: dict) -> dict:
        category = (f.get("category") or "").lower()
        layer = 7 if category in _AGENTIC_CATEGORIES else 6
        severity = _SEVERITY_MAP.get(str(f.get("severity", "")).upper(), "MEDIUM")
        finding_id = str(f.get("finding_id") or f.get("rule_id") or "skillspector-finding")
        return {
            "finding_id": finding_id,
            "fingerprint": f.get("match_fingerprint") or finding_id,
            "rule_id": f.get("rule_id") or "UNKNOWN",
            "engine": self.name,
            "layer": layer,
            "title": f.get("message") or f.get("category") or f.get("rule_id") or "SkillSpector finding",
            "description": f.get("explanation") or f.get("message"),
            "rule_lifecycle": "ACTIVE",
            "implementation_capability": "IMPLEMENTED",
            "evaluation_result": "FINDING",
            "severity": severity,
            "confidence": _confidence_bucket(f.get("confidence")),
            "location": {
                "target": f.get("file"),
                "file": f.get("file"),
                "start_line": f.get("start_line"),
                "end_line": f.get("end_line"),
            },
            "policy_evidence": {"state": "UNKNOWN", "reason": "not assessed by SkillSpector"},
            "remediation": {"implementation_guidance": f.get("remediation")} if f.get("remediation") else {},
            "coverage_status": "INTEGRATED",
        }
