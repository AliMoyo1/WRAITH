"""Strix engine adapter.

Strix (usestrix/strix) is an autonomous pentesting agent. WRAITH consumes its
**public** output, not its internal skill names: Strix emits a GitHub-compatible
SARIF 2.1.0 `findings.sarif` sidecar, which this adapter parses via
adapters.sarif and normalizes to the WRAITH finding schema.

Strix is a dynamic engine: a live run needs Docker and an LLM key, and it is
invoked non-interactively (`strix -t <target> -n`). The adapter locates the
`findings.sarif` sidecar in the run directory after the run. As with every
adapter, the subprocess runner is injectable, so normalization is fully tested
without Strix installed.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from .base import AdapterRequest, EngineAdapter, SubprocessResult, run_subprocess, scrubbed_env
from .sarif import SarifResult, parse_sarif_results

# Keyword buckets (matched against rule id + message + tags) -> WRAITH layer.
_LAYER_KEYWORDS = [
    (7, ("prompt", "llm", "mcp", "agent", "memory", "rag", "tool-poison", "tool poison")),
    (5, ("aws", "azure", "gcp", "s3", "iam", "kubernetes", "k8s", "cloud")),
    (4, ("port", "ssh", "smtp", "smb", "kerberos", "ldap", "dns", "network")),
    (3, ("graphql", "jwt", "oauth", "bola", "api")),
    (2, ("xss", "sqli", "sql injection", "ssrf", "csrf", "idor", "web", "xxe")),
]


def _severity(level: str, security_severity: float | None) -> str:
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


class StrixAdapter(EngineAdapter):
    name = "strix"

    def __init__(
        self,
        engine_path: str | Path,
        command_prefix: list[str] | None = None,
        pinned_commit: str | None = None,
        default_layer: int = 2,
    ):
        self.engine_path = Path(engine_path)
        self._command_prefix = command_prefix
        self.pinned_commit = pinned_commit
        self.default_layer = default_layer

    # ---- availability ----------------------------------------------------
    def _resolve_command(self) -> list[str] | None:
        if self._command_prefix:
            return list(self._command_prefix)
        for rel in ("Scripts/strix.exe", "bin/strix"):
            venv_bin = self.engine_path / ".venvs" / "strix" / rel
            if venv_bin.exists():
                return [str(venv_bin)]
        found = shutil.which("strix")
        if found:
            return [found]
        return [sys.executable, "-m", "strix"]

    def is_available(self) -> tuple[bool, str]:
        if not self.engine_path.exists():
            return False, f"engine path not found: {self.engine_path}"
        if self._resolve_command() is None:
            return False, "no runnable strix command resolved"
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
        import tempfile

        workdir = Path(tempfile.mkdtemp(prefix="wraith-strix-"))
        full = [*cmd, "-t", request.target, "-n"]
        scan_mode = request.options.get("scan_mode")
        if scan_mode:
            full += ["-m", str(scan_mode)]
        result = run_subprocess(full, cwd=workdir, timeout=request.timeout_seconds)
        sarif = self._locate_sarif(workdir)
        if sarif is not None:
            try:
                return SubprocessResult(
                    returncode=result.returncode, stdout=sarif.read_text(encoding="utf-8"),
                    stderr=result.stderr, timed_out=result.timed_out,
                )
            except OSError:
                pass
        return result

    @staticmethod
    def _locate_sarif(workdir: Path) -> Path | None:
        candidates = sorted(
            workdir.rglob("findings.sarif"),
            key=lambda p: p.stat().st_mtime if p.exists() else 0,
            reverse=True,
        )
        return candidates[0] if candidates else None

    # ---- normalization ---------------------------------------------------
    def _normalize(self, raw_output: str) -> list[dict]:
        return [self._map(r) for r in parse_sarif_results(raw_output)]

    def _layer_for(self, result: SarifResult) -> int:
        haystack = " ".join([result.rule_id, result.message, *result.tags]).lower()
        for layer, keywords in _LAYER_KEYWORDS:
            if any(k in haystack for k in keywords):
                return layer
        return self.default_layer

    def _map(self, r: SarifResult) -> dict:
        fingerprint = r.fingerprint or f"{r.rule_id}:{r.file}:{r.start_line}"
        return {
            "finding_id": f"strix-{fingerprint}",
            "fingerprint": fingerprint,
            "rule_id": r.rule_id,
            "engine": self.name,
            "layer": self._layer_for(r),
            "title": r.message or r.rule_id,
            "description": r.message or None,
            "rule_lifecycle": "ACTIVE",
            "implementation_capability": "IMPLEMENTED",
            "evaluation_result": "FINDING",
            "severity": _severity(r.level, r.security_severity),
            "confidence": "MEDIUM",  # SARIF has no standard confidence field
            "location": {"target": r.file, "file": r.file, "start_line": r.start_line, "end_line": r.end_line},
            "policy_evidence": {"state": "UNKNOWN", "reason": "not assessed by Strix"},
            "remediation": {},
            "coverage_status": "INTEGRATED",
        }
