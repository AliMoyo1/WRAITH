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
) -> None:
    """Run the adapters, store findings per scan, and update the scan status.

    A worker failure marks the scan errored; it never crashes the service.
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
