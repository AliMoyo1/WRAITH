"""Process supervisor: run engine adapters with bounded concurrency and a kill-switch.

Executes a set of adapter jobs through a thread pool capped at `max_parallel`
(adapters are subprocess-bound, so threads are the right tool). One engine
failing never crashes the run: an exception becomes an ERROR result. The
kill-switch (an in-process flag and/or the CLI's `.killed` file) stops any job
that has not started yet; jobs already running continue to their own timeout.
Every job start/finish is recorded through the redacting structured logger.

WRAITH.md orchestrator settings: max_parallel, kill_switch_timeout. Addresses the
process-supervisor part of audit #6.
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from adapters.base import AdapterRequest, AdapterResult, EngineAdapter
from obs import get_logger, log_event


@dataclass
class Job:
    adapter: EngineAdapter
    request: AdapterRequest


def _incomplete(reason: str) -> dict:
    return {"status": "INCOMPLETE", "reason": reason}


class Supervisor:
    def __init__(
        self,
        max_parallel: int = 3,
        kill_flag_path: str | Path | None = None,
        logger: logging.Logger | None = None,
    ):
        self.max_parallel = max(1, int(max_parallel))
        self.kill_flag_path = Path(kill_flag_path) if kill_flag_path else None
        self._kill = threading.Event()
        self.logger = logger or get_logger("wraith.supervisor")

    def kill(self) -> None:
        self._kill.set()

    def _killed(self) -> bool:
        if self._kill.is_set():
            return True
        return self.kill_flag_path is not None and self.kill_flag_path.exists()

    def _run_job(self, job: Job) -> AdapterResult:
        name = job.adapter.name
        if self._killed():
            log_event(self.logger, logging.WARNING, "job.killed", engine=name, target=job.request.target)
            return AdapterResult(engine=name, status="KILLED", coverage=_incomplete("kill-switch"))
        log_event(self.logger, logging.INFO, "job.start", engine=name, target=job.request.target)
        try:
            result = job.adapter.run(job.request)
        except Exception as exc:  # one engine must never crash the whole run
            log_event(self.logger, logging.ERROR, "job.error", engine=name, error=str(exc))
            return AdapterResult(engine=name, status="ERROR", errors=[str(exc)], coverage=_incomplete("exception"))
        count = len(result.findings)
        log_event(self.logger, logging.INFO, "job.done", engine=name, status=result.status, findings=count)
        return result

    def run(self, jobs: list[Job]) -> list[AdapterResult]:
        results: list[AdapterResult | None] = [None] * len(jobs)
        log_event(self.logger, logging.INFO, "run.start", jobs=len(jobs), max_parallel=self.max_parallel)
        with ThreadPoolExecutor(max_workers=self.max_parallel) as pool:
            futures = {pool.submit(self._run_job, job): i for i, job in enumerate(jobs)}
            for future in as_completed(futures):
                results[futures[future]] = future.result()
        out = [r for r in results if r is not None]
        statuses: dict[str, int] = {}
        for r in out:
            statuses[r.status] = statuses.get(r.status, 0) + 1
        log_event(self.logger, logging.INFO, "run.done", results=len(out), statuses=statuses)
        return out
