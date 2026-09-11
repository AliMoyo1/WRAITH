"""Semgrep adapter: multi-language static analysis (SAST).

Semgrep emits SARIF 2.1 with ``--sarif`` on stdout; the shared SarifCliAdapter
parses it via adapters.sarif_mapper. Semgrep is operator-installed (LGPL-2.1),
never bundled, and is static and target-read-only (Layer 6).

The ruleset defaults to ``--config auto`` (the community registry); override with
``request.options["config"]`` (for example a local rules path).
"""

from __future__ import annotations

from .base import AdapterRequest
from .sarif_cli import SarifCliAdapter


class SemgrepAdapter(SarifCliAdapter):
    name = "semgrep"
    binary = "semgrep"
    default_layer = 6

    def _argv(self, command: list[str], request: AdapterRequest) -> list[str]:
        config = str(request.options.get("config", "auto"))
        return [
            *command, "scan", "--sarif", "--config", config, "--metrics", "off",
            request.target,
        ]
