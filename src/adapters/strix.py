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
from .sarif import parse_sarif_results
from .sarif_mapper import to_finding


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
        # Layer inference, severity, and the finding shape are shared with every
        # other SARIF engine; see adapters.sarif_mapper.
        return [
            to_finding(r, self.name, self.default_layer)
            for r in parse_sarif_results(raw_output)
        ]
