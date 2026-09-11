"""In-process scan worker for the Runner.

A scan is enqueued by POST /v1/scans and run off the request thread: the worker runs
the engine adapters through the supervisor, writes findings to a per-scan encrypted
result store (isolated by construction, since the store key is derived per scan id
and the Scan row is tenant-scoped), and updates the scan status. The executor is
injectable, so tests run the job inline and production runs it on a small thread
pool; a durable external queue can replace this later without changing the API.

Sub-phase 4 supports only the defensive, target-read-only ``sast`` track. Offensive
tracks and their engines land in sub-phase 6.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from sqlalchemy.orm import Session, sessionmaker

from adapters import (
    AdapterRequest,
    EngineAdapter,
    SemgrepAdapter,
    SkillSpectorAdapter,
    TrivyAdapter,
)
from store import ResultStore
from supervisor import Job, Supervisor

from . import repository


class Executor(Protocol):
    def submit(self, fn: Callable[[], None]) -> None: ...


class InlineExecutor:
    """Runs the job synchronously (tests: the scan completes before POST returns)."""

    def submit(self, fn: Callable[[], None]) -> None:
        fn()


class BackgroundExecutor:
    """Runs jobs on a small thread pool so POST /v1/scans returns immediately."""

    def __init__(self, max_workers: int = 2) -> None:
        self._pool = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="wraith-runner"
        )

    def submit(self, fn: Callable[[], None]) -> None:
        self._pool.submit(fn)


class Sandbox(Protocol):
    def available(self) -> tuple[bool, str]: ...
    def run(self, adapters: list[EngineAdapter], target: str, timeout_seconds: float) -> list[dict]: ...


class CubeSandbox:
    """Hardware-isolated execution (CubeSandbox on x86_64 Linux + KVM), one sandbox
    per run, torn down after.

    The live integration is a deployment step (it needs KVM and a pinned image
    digest), so here it reports unavailable. That is the fail-closed default:
    offensive engines never run outside isolation.
    """

    def available(self) -> tuple[bool, str]:
        return False, "CubeSandbox not configured (needs x86_64 Linux + KVM and a pinned image)"

    def run(self, adapters: list[EngineAdapter], target: str, timeout_seconds: float) -> list[dict]:
        raise RuntimeError("CubeSandbox is not available in this environment")


def default_adapters(track: str, engines_dir: str | Path) -> list[EngineAdapter]:
    """Build the defensive adapters for a track. Absent engines report UNAVAILABLE."""
    root = Path(engines_dir)
    if track == "sast":
        return [
            SkillSpectorAdapter(root / "skillspector"),
            TrivyAdapter(root / "trivy"),
            SemgrepAdapter(root / "semgrep"),
        ]
    return []


def run_scan(
    session_factory: sessionmaker[Session],
    result_root: str | Path,
    result_key: bytes,
    adapters: list[EngineAdapter],
    tenant_id: str,
    scan_id: str,
    target: str,
    timeout_seconds: float = 300.0,
    sandbox: Sandbox | None = None,
) -> None:
    """Run the adapters, store findings per scan, and update the scan status.

    A defensive scan runs the adapters directly. An offensive scan passes a sandbox:
    the adapters run inside it, and if it is unavailable the scan fails closed (no
    engine runs outside isolation). A worker failure marks the scan errored; it
    never crashes the service.
    """
    with session_factory() as session:
        # A scan queued before a kill was engaged does not run: mark it killed.
        if repository.is_killed(session, tenant_id):
            scan = repository.get_scan(session, tenant_id, scan_id)
            if scan is not None:
                repository.set_scan_status(session, scan, "killed", datetime.now(UTC).isoformat())
            return
    status = "completed"
    try:
        if sandbox is not None:
            ok, reason = sandbox.available()
            if not ok:
                raise RuntimeError(f"sandbox unavailable: {reason}")
            findings = sandbox.run(adapters, target, timeout_seconds)
        else:
            jobs = [
                Job(adapter=a, request=AdapterRequest(target=target, timeout_seconds=timeout_seconds))
                for a in adapters
            ]
            results = Supervisor(max_parallel=2).run(jobs)
            findings = [f for r in results for f in r.findings]
        store = ResultStore(result_root, scan_id, result_key, actor=f"runner:{tenant_id}")
        for finding in findings:
            store.put_finding(finding)
    except Exception:
        logging.getLogger("wraith.runner").exception("scan %s failed", scan_id)
        status = "error"
    with session_factory() as session:
        scan = repository.get_scan(session, tenant_id, scan_id)
        if scan is not None:
            repository.set_scan_status(session, scan, status, datetime.now(UTC).isoformat())
