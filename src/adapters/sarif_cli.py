"""Base adapter for external CLI engines that emit SARIF 2.1 on stdout.

Trivy and Semgrep are static, target-read-only scanners the operator installs
(never bundled). They differ only in the binary name and the argv they build; the
availability check, version probe, and SARIF normalization are shared here.
Findings go through adapters.sarif_mapper, so they match every other SARIF engine.

Availability is by ``shutil.which`` (these are PATH binaries, not cloned repos), so
``engine_path`` from the loader is unused. ``command_prefix`` is injectable for
tests, exactly as in the Strix adapter.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from .base import AdapterRequest, EngineAdapter, SubprocessResult, run_subprocess
from .sarif import parse_sarif_results
from .sarif_mapper import to_finding


class SarifCliAdapter(EngineAdapter):
    """Shared behavior for a SARIF-on-stdout CLI engine.

    Subclasses set ``name`` and ``binary`` and implement ``_argv``.
    """

    binary: str = ""
    default_layer: int = 6

    def __init__(
        self,
        engine_path: str | Path,
        pinned_commit: str | None = None,
        command_prefix: list[str] | None = None,
    ):
        self.engine_path = Path(engine_path)
        self.pinned_commit = pinned_commit
        self._command_prefix = command_prefix

    def _resolve_command(self) -> list[str] | None:
        if self._command_prefix:
            return list(self._command_prefix)
        found = shutil.which(self.binary)
        return [found] if found else None

    def is_available(self) -> tuple[bool, str]:
        if self._resolve_command() is None:
            return False, f"{self.binary} not found on PATH"
        return True, "available"

    def engine_version(self) -> str | None:
        # Best effort; skip the subprocess when a test injects a command prefix.
        if self._command_prefix is not None:
            return self.pinned_commit
        found = shutil.which(self.binary)
        if not found:
            return self.pinned_commit
        result = run_subprocess([found, "--version"], cwd=None, timeout=10)
        return result.stdout.strip() or self.pinned_commit

    def _argv(self, command: list[str], request: AdapterRequest) -> list[str]:
        """Build the full argv for a scan. Implemented by each engine."""
        raise NotImplementedError

    def _default_runner(self, request: AdapterRequest) -> SubprocessResult:
        command = self._resolve_command()
        assert command is not None  # guarded by is_available before run()
        return run_subprocess(
            self._argv(command, request), cwd=None, timeout=request.timeout_seconds
        )

    def _normalize(self, raw_output: str) -> list[dict]:
        return [
            to_finding(r, self.name, self.default_layer)
            for r in parse_sarif_results(raw_output)
        ]
