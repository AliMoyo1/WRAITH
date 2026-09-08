"""Process-supervisor tests: concurrency, ordering, isolation, kill-switch."""

from __future__ import annotations

import io
import logging

from adapters.base import AdapterRequest, AdapterResult, EngineAdapter, SubprocessResult
from obs import get_logger
from supervisor import Job, Supervisor


class FakeAdapter(EngineAdapter):
    def __init__(self, name="fake", findings=0, boom=False):
        self.name = name
        self._findings = findings
        self._boom = boom

    def is_available(self):
        return True, "ok"

    def _default_runner(self, request):
        return SubprocessResult(0, "", "")

    def _normalize(self, raw):
        return []

    def run(self, request, runner=None):
        if self._boom:
            raise RuntimeError("kaboom")
        return AdapterResult(engine=self.name, status="OK", findings=[{}] * self._findings)


def _supervisor(**kw):
    return Supervisor(logger=get_logger("wraith.test.sup", stream=io.StringIO(), level=logging.ERROR), **kw)


def _jobs(*adapters):
    return [Job(adapter=a, request=AdapterRequest(target="t")) for a in adapters]


def test_runs_all_jobs():
    results = _supervisor().run(_jobs(FakeAdapter("a", findings=2), FakeAdapter("b", findings=1)))
    assert len(results) == 2
    assert {r.engine for r in results} == {"a", "b"}
    assert all(r.status == "OK" for r in results)


def test_results_order_preserved():
    adapters = [FakeAdapter(f"fake{i}") for i in range(5)]
    results = _supervisor(max_parallel=2).run(_jobs(*adapters))
    assert [r.engine for r in results] == [f"fake{i}" for i in range(5)]


def test_exception_becomes_error_and_does_not_crash():
    results = _supervisor().run(_jobs(FakeAdapter("ok"), FakeAdapter("bad", boom=True)))
    by = {r.engine: r for r in results}
    assert by["ok"].status == "OK"
    assert by["bad"].status == "ERROR" and "kaboom" in by["bad"].errors[0]


def test_kill_before_run_marks_all_killed():
    sup = _supervisor()
    sup.kill()
    results = sup.run(_jobs(FakeAdapter("a"), FakeAdapter("b")))
    assert all(r.status == "KILLED" for r in results)


def test_kill_flag_file_marks_killed(tmp_path):
    flag = tmp_path / ".killed"
    flag.write_text("x", encoding="utf-8")
    results = _supervisor(kill_flag_path=flag).run(_jobs(FakeAdapter("a")))
    assert results[0].status == "KILLED"


def test_max_parallel_floor():
    assert _supervisor(max_parallel=0).max_parallel == 1
