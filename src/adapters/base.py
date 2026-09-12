"""Engine-adapter contract.

An engine adapter runs an external security engine as an isolated subprocess and
returns findings normalized to the WRAITH finding schema (schemas/finding.schema.json).

Design (audit High #4 and #6):
  * Each adapter is an external process with a versioned JSON contract, a strict
    timeout, a constrained working directory, and a pinned engine version.
  * The subprocess does not inherit WRAITH's own secrets (the signing and result
    keys are scrubbed from its environment).
  * Network isolation is the operator's responsibility (container or firewall);
    Python cannot enforce an OS-level network policy portably. run_subprocess
    documents this rather than pretending to enforce it.
  * A rule/engine whose capability is unavailable yields NOT_EVALUATED, never a
    passing result (capability discipline carried over from the taxonomy work).
"""

from __future__ import annotations

import os
import subprocess
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

ADAPTER_CONTRACT_VERSION = "1.0"

# Environment allowlist: only these variables reach a scanned engine subprocess.
# An allowlist (not a blacklist) is the safe default: a new WRAITH secret, or any
# other sensitive variable in the service environment, is excluded automatically
# rather than requiring someone to remember to add it to a denylist. Engine-specific
# configuration is passed as CLI arguments, never inherited from the environment.
# Names are matched case-insensitively (Windows env vars vary in case).
_ENV_ALLOWLIST = frozenset(
    name.upper()
    for name in (
        # POSIX essentials
        "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "TZ", "TMPDIR",
        "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_NUMERIC", "LC_MESSAGES",
        # TLS trust stores some engines need to fetch over HTTPS
        "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE",
        # XDG dirs (engine caches)
        "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
        # Windows essentials
        "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "HOMEDRIVE", "HOMEPATH",
        "USERPROFILE", "PUBLIC", "TEMP", "TMP", "APPDATA", "LOCALAPPDATA",
        "PROGRAMDATA", "PATHEXT", "COMSPEC", "OS", "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER",
        "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432",
        "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)", "COMMONPROGRAMW6432",
    )
)


@dataclass
class AdapterRequest:
    target: str
    scan_id: str = "adhoc"
    timeout_seconds: float = 300.0
    no_llm: bool = True  # deterministic by default; LLM augmentation is opt-in
    options: dict = field(default_factory=dict)


@dataclass
class SubprocessResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass
class AdapterResult:
    engine: str
    status: str  # OK | ERROR | UNAVAILABLE | TIMEOUT
    contract_version: str = ADAPTER_CONTRACT_VERSION
    engine_version: str | None = None
    findings: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    coverage: dict = field(default_factory=dict)


def _to_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def scrubbed_env() -> dict[str, str]:
    """The subprocess environment: only allowlisted variables (fail closed).

    Everything not in ``_ENV_ALLOWLIST`` is dropped, so no WRAITH secret (signing,
    result, platform, evidence, or database keys) and no other unexpected variable
    reaches a scanned engine. Matched case-insensitively.
    """
    return {k: v for k, v in os.environ.items() if k.upper() in _ENV_ALLOWLIST}


def run_subprocess(cmd: list[str], cwd: str | Path | None, timeout: float, env: dict | None = None) -> SubprocessResult:
    """Run an engine command with a hard timeout and captured output.

    Network access is NOT restricted here; run adapters inside a container or
    a firewalled sandbox when scanning hostile targets. The environment is
    scrubbed of WRAITH secrets by default.
    """
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env if env is not None else scrubbed_env(),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return SubprocessResult(returncode=-1, stdout=_to_text(exc.stdout), stderr=_to_text(exc.stderr), timed_out=True)
    except (OSError, ValueError) as exc:
        return SubprocessResult(returncode=-1, stdout="", stderr=str(exc))
    return SubprocessResult(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


# A runner takes a request and returns raw subprocess output. Injectable for tests.
Runner = Callable[[AdapterRequest], SubprocessResult]


class EngineAdapter(ABC):
    name: str = "base"
    contract_version: str = ADAPTER_CONTRACT_VERSION

    @abstractmethod
    def is_available(self) -> tuple[bool, str]:
        """Return (available, reason). Reason explains unavailability."""

    @abstractmethod
    def _default_runner(self, request: AdapterRequest) -> SubprocessResult:
        """Invoke the real engine subprocess and return its raw output."""

    @abstractmethod
    def _normalize(self, raw_output: str) -> list[dict]:
        """Parse raw engine output and return WRAITH-normalized findings."""

    def engine_version(self) -> str | None:
        """Best-effort engine version (for example the pinned commit)."""
        return None

    def run(self, request: AdapterRequest, runner: Runner | None = None) -> AdapterResult:
        available, reason = self.is_available()
        if not available:
            # Capability discipline: unavailable engine is NOT_EVALUATED, not a pass.
            return AdapterResult(
                engine=self.name, status="UNAVAILABLE", errors=[reason],
                coverage={"status": "NOT_EVALUATED", "reason": reason},
            )
        run = runner or self._default_runner
        result = run(request)
        if result.timed_out:
            return AdapterResult(
                engine=self.name, status="TIMEOUT",
                errors=[f"engine timed out after {request.timeout_seconds}s"],
                coverage={"status": "INCOMPLETE", "reason": "timeout"},
            )
        if result.returncode != 0:
            return AdapterResult(
                engine=self.name, status="ERROR",
                errors=[result.stderr.strip() or f"exit code {result.returncode}"],
                coverage={"status": "INCOMPLETE", "reason": "engine error"},
            )
        try:
            findings = self._normalize(result.stdout)
        except (ValueError, KeyError, TypeError) as exc:
            return AdapterResult(
                engine=self.name, status="ERROR",
                errors=[f"could not parse engine output: {exc}"],
                coverage={"status": "INCOMPLETE", "reason": "unparseable output"},
            )
        return AdapterResult(
            engine=self.name, status="OK", findings=findings,
            engine_version=self.engine_version(),
            coverage={"status": "INTEGRATED", "finding_count": len(findings)},
        )
