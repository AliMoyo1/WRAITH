"""Trivy adapter: filesystem and image vulnerability, secret, and misconfig scanning.

Trivy emits SARIF 2.1 with ``--format sarif`` on stdout; the shared SarifCliAdapter
parses it via adapters.sarif_mapper. Trivy is operator-installed (Apache-2.0),
never bundled, and is static and target-read-only (Layer 6).

Target handling: a filesystem path is scanned with ``trivy fs``; set
``request.options["scan"] = "image"`` to scan a container image ref with
``trivy image``.
"""

from __future__ import annotations

from .base import AdapterRequest
from .sarif_cli import SarifCliAdapter

_SEVERITIES = "CRITICAL,HIGH,MEDIUM"


class TrivyAdapter(SarifCliAdapter):
    name = "trivy"
    binary = "trivy"
    default_layer = 6

    def _argv(self, command: list[str], request: AdapterRequest) -> list[str]:
        subcommand = "image" if request.options.get("scan") == "image" else "fs"
        argv = [*command, subcommand, "--format", "sarif", "--severity", _SEVERITIES]
        if subcommand == "fs":
            argv += ["--scanners", "vuln,secret,misconfig"]
        argv.append(request.target)
        return argv
