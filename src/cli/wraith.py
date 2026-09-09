#!/usr/bin/env python3
"""WRAITH CLI - unified entry point for all engines.

Phase 0. The engine adapters are still stubs, but the safety surface is real:
`scan` refuses out-of-scope targets and refuses to run while the kill-switch is
engaged, `scope` and `engage` persist state, and `engage start` writes a signed,
expiring engagement. See WRAITH.md Section 11.1.

Exit codes:
  0  ok
  2  refused (out of scope, scope disabled, or missing configuration)
  3  kill-switch engaged
"""

from __future__ import annotations

import argparse
import logging
import sys
import uuid
from datetime import timedelta
from pathlib import Path

# Allow running as a plain script: put the src/ root on the path.
_SRC = Path(__file__).resolve().parents[1]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import config  # noqa: E402
from adapters import ADAPTERS, AdapterRequest  # noqa: E402
from obs import get_logger, log_event  # noqa: E402
from orchestrator import Engagement, Orchestrator, Scope, Track, now_utc  # noqa: E402
from orchestrator.scope import classify_target  # noqa: E402
from redteam import (  # noqa: E402
    ChecklistGenerator,
    GenerateRequest,
    MethodologyGenerator,
    load_capabilities,
    resolve_for_target,
)
from store import ResultStore, ResultStoreError  # noqa: E402
from supervisor import Job, Supervisor  # noqa: E402

__version__ = "2.1"

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_DIR = _REPO_ROOT / "config"
_DEFAULT_SCOPE = _CONFIG_DIR / "scope.yaml"
_DEFAULT_ENGAGE = _CONFIG_DIR / "engagement.json"
_KILL_FLAG = _CONFIG_DIR / ".killed"
_RESULTS_ROOT = _REPO_ROOT / "results"
_ENGINE_DIRS = {"skillspector": "repos/SkillSpector", "strix": "repos/strix"}


def _scope_path(args) -> Path:
    return Path(getattr(args, "scope", None) or _DEFAULT_SCOPE)


def _load_scope_or_empty(path: Path) -> Scope:
    if path.exists():
        return config.load_scope(path)
    return Scope()


# track -> engine domains; "all" selects by target kind (static repo vs dynamic host).
_TRACK_DOMAINS = {"skillspector": {"sast", "agentic"}, "strix": {"web", "api", "network", "cloud"}}


def _adapters_for(track: str, target: str) -> list[str]:
    kind = classify_target(target)
    static_ok = kind == "repo_path"
    dynamic_ok = kind in ("url", "domain", "cidr")
    selected: list[str] = []
    for name, domains in _TRACK_DOMAINS.items():
        if track == "all":
            if (name == "skillspector" and static_ok) or (name == "strix" and dynamic_ok):
                selected.append(name)
        elif track in domains:
            selected.append(name)
    return selected


def _authorize_scan(args) -> tuple[int | None, Engagement | None]:
    """Gate the scan. With an engagement, use the kernel; otherwise a scope pre-flight.

    Returns (early_exit_code_or_None, engagement_or_None).
    """
    engage_path = Path(getattr(args, "engagement_file", None) or _DEFAULT_ENGAGE)
    if engage_path.exists():
        try:
            key = config.signing_key()
        except RuntimeError as exc:
            print(str(exc))
            return 2, None
        engagement = config.load_engagement(engage_path)
        orch = Orchestrator(key)
        try:
            orch.start_engagement(engagement)
            orch.require_authorization(Track.SAST_AGENTIC, args.target)  # analysis gate: engagement + scope
        except PermissionError as exc:
            print(f"refused: {exc}")
            return 2, None
        return None, engagement
    path = _scope_path(args)
    if not path.exists():
        print(f"no scope file at {path}; run 'wraith scope add <target>' or 'wraith engage start' first")
        return 2, None
    scope = config.load_scope(path)
    if not scope.enabled:
        print("scope is not enabled (fail closed); set scope.enabled: true after review")
        return 2, None
    if not scope.allows(args.target):
        print(f"refused: {args.target} is not in the authorized scope")
        return 2, None
    return None, None


def cmd_scan(args) -> int:
    logger = get_logger("wraith.scan")
    if _KILL_FLAG.exists():
        print("kill-switch engaged; run 'wraith kill --reset' to clear")
        return 3
    code, engagement = _authorize_scan(args)
    if code is not None:
        return code
    if args.dry_run:
        print(f"in scope: {args.target} (track={args.track}); dry-run, no engines invoked")
        return 0
    names = _adapters_for(args.track, args.target)
    if not names:
        print(f"no engine applies to {args.target} for track={args.track}")
        return 0
    jobs = []
    for name in names:
        adapter, err = _build_adapter(name)
        if err:
            print(err)
            continue
        jobs.append(Job(adapter=adapter, request=AdapterRequest(target=args.target, timeout_seconds=args.timeout)))
    results = Supervisor(max_parallel=args.max_parallel, kill_flag_path=_KILL_FLAG, logger=logger).run(jobs)
    for r in results:
        print(f"{r.engine}: {r.status} ({len(r.findings)} finding(s), coverage={r.coverage.get('status')})")
    findings = [f for r in results for f in r.findings]
    return _persist_scan(args, engagement, findings, logger)


def _persist_scan(args, engagement: Engagement | None, findings: list[dict], logger) -> int:
    if engagement is None:
        print(f"no engagement active; {len(findings)} finding(s) not persisted (run 'wraith engage start')")
        if args.report:
            _write_report(args.report, None, findings)
            print(f"ephemeral report written to {args.report}")
        return 0
    try:
        result_key = config.result_key()
    except RuntimeError:
        print("WRAITH_RESULT_KEY not set; findings not persisted")
        return 0
    store = ResultStore(_RESULTS_ROOT, engagement.id, result_key, actor="scan")
    for finding in findings:
        store.put_finding(finding)
    log_event(logger, logging.INFO, "scan.persisted", engagement=engagement.id, stored=len(findings))
    print(f"stored {len(findings)} finding(s) under engagement {engagement.id}")
    if args.report:
        out = store.export(args.report)
        print(f"report written to {out}")
    return 0


def _write_report(path: str, engagement_id: str | None, findings: list[dict]) -> None:
    import json

    payload = {"engagement_id": engagement_id, "findings": findings}
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def cmd_scope(args) -> int:
    path = _scope_path(args)
    scope = _load_scope_or_empty(path)
    if args.action == "list":
        print(f"enabled: {scope.enabled}")
        for name, lst in (("allow", scope.allow), ("block", scope.block)):
            print(f"[{name}] cidrs={lst.cidrs} domains={lst.domains} urls={lst.urls} repo_paths={lst.repo_paths}")
        return 0
    if not args.target:
        print("target required for add/rm")
        return 2
    kind = classify_target(args.target)
    bucket = {
        "url": scope.allow.urls,
        "cidr": scope.allow.cidrs,
        "repo_path": scope.allow.repo_paths,
        "domain": scope.allow.domains,
    }[kind]
    if args.action == "add":
        if args.target not in bucket:
            bucket.append(args.target)
        config.save_scope(path, scope)
        print(f"added {args.target} to allow.{kind}s")
        return 0
    if args.action == "rm":
        for entries in (scope.allow.cidrs, scope.allow.domains, scope.allow.urls, scope.allow.repo_paths):
            if args.target in entries:
                entries.remove(args.target)
        config.save_scope(path, scope)
        print(f"removed {args.target}")
        return 0
    return 2


def cmd_engage(args) -> int:
    engage_path = Path(getattr(args, "engagement_file", None) or _DEFAULT_ENGAGE)
    if args.action == "start":
        try:
            key = config.signing_key()
        except RuntimeError as exc:
            print(str(exc))
            return 2
        scope = _load_scope_or_empty(_scope_path(args))
        if not scope.enabled:
            print("refused: scope is not enabled; enable and review scope before starting an engagement")
            return 2
        if not args.by or not args.by.strip():
            print("refused: --by (authorizing operator) is required")
            return 2
        started = now_utc()
        eng = Engagement(
            id=str(uuid.uuid4()),
            authorized_by=args.by.strip(),
            approved_at=started.isoformat(),
            expires_at=(started + timedelta(hours=args.hours)).isoformat(),
            scope=scope,
        ).sign(key)
        _save_engagement(engage_path, eng)
        print(f"engagement {eng.id} started by {eng.authorized_by}, expires {eng.expires_at}")
        return 0
    if args.action == "close":
        if not engage_path.exists():
            print("no engagement to close")
            return 2
        eng = config.load_engagement(engage_path)
        eng.open = False
        _save_engagement(engage_path, eng)
        print(f"engagement {eng.id} closed")
        return 0
    return 2


def _save_engagement(path: Path, eng: Engagement) -> None:
    node = {
        "id": eng.id,
        "authorized_by": eng.authorized_by,
        "approved_at": eng.approved_at,
        "expires_at": eng.expires_at,
        "open": eng.open,
        "signature": eng.signature,
        "scope": {
            "enabled": eng.scope.enabled,
            "allow_metadata": eng.scope.allow_metadata,
            "block_private": eng.scope.block_private,
            "allowlist": {
                "cidrs": eng.scope.allow.cidrs,
                "domains": eng.scope.allow.domains,
                "urls": eng.scope.allow.urls,
                "repo_paths": eng.scope.allow.repo_paths,
            },
            "blocklist": {
                "cidrs": eng.scope.block.cidrs,
                "domains": eng.scope.block.domains,
                "urls": eng.scope.block.urls,
                "repo_paths": eng.scope.block.repo_paths,
            },
        },
    }
    config._dump_mapping(path, {"engagement": node})


def cmd_kill(args) -> int:
    if args.reset:
        if _KILL_FLAG.exists():
            _KILL_FLAG.unlink()
        print("kill-switch reset")
        return 0
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _KILL_FLAG.write_text(now_utc().isoformat(), encoding="utf-8")
    print("kill-switch engaged; all scans refused until reset")
    return 0


def cmd_report(args) -> int:
    try:
        key = config.result_key()
    except RuntimeError as exc:
        print(str(exc))
        return 2
    try:
        store = ResultStore(_RESULTS_ROOT, args.engagement, key, actor=args.actor or "cli")
    except ResultStoreError as exc:
        print(f"refused: {exc}")
        return 2
    findings = store.list_findings()
    intact = store.verify_audit()
    print(f"engagement {args.engagement}: {len(findings)} finding(s); audit chain {'intact' if intact else 'TAMPERED'}")
    if args.export:
        try:
            out = store.export(args.export)
        except ResultStoreError as exc:
            print(f"export failed: {exc}")
            return 2
        print(f"exported {len(findings)} finding(s) to {out}")
    return 0 if intact else 2


def _build_adapter(name: str):
    if name not in ADAPTERS:
        return None, f"unknown engine: {name} (known: {', '.join(sorted(ADAPTERS))})"
    engine_path = _REPO_ROOT / _ENGINE_DIRS.get(name, f"repos/{name}")
    pin = None
    lock = _CONFIG_DIR / "engines.lock.yaml"
    if lock.exists():
        data = config._load_mapping(lock)
        pin = ((data.get("engines") or {}).get(name) or {}).get("commit")
    return ADAPTERS[name](engine_path, pinned_commit=pin), None


def cmd_engine(args) -> int:
    if args.action == "list":
        for name in sorted(ADAPTERS):
            print(name)
        return 0
    if not args.name:
        print("engine name required for check/run")
        return 2
    adapter, err = _build_adapter(args.name)
    if err:
        print(err)
        return 2
    if args.action == "check":
        ok, reason = adapter.is_available()
        print(f"{args.name}: {'available' if ok else 'unavailable'} ({reason})")
        return 0 if ok else 1
    # run
    if not args.target:
        print("target required for run")
        return 2
    request = AdapterRequest(target=args.target, timeout_seconds=args.timeout, no_llm=not args.llm)
    result = adapter.run(request)
    coverage = result.coverage.get("status")
    print(f"{args.name}: status={result.status} findings={len(result.findings)} coverage={coverage}")
    for e in result.errors:
        print(f"  error: {e}")
    if args.store and result.status == "OK" and result.findings:
        try:
            key = config.result_key()
        except RuntimeError as exc:
            print(str(exc))
            return 2
        store = ResultStore(_RESULTS_ROOT, args.store, key, actor=f"engine:{args.name}")
        for finding in result.findings:
            store.put_finding(finding)
        print(f"stored {len(result.findings)} finding(s) under engagement {args.store}")
    return 0 if result.status in ("OK", "UNAVAILABLE") else 1



_REDTEAM_BANNER = """
╔══════════════════════════════════════════════════════════════════════════╗
║  WRAITH Red Team Annex                                                ║
║  Authorized methodology generator for pentest engagements.             ║
║  USE ONLY WITH WRITTEN AUTHORIZATION.                                 ║
╚══════════════════════════════════════════════════════════════════════════╝
"""


def cmd_redteam(args) -> int:
    """Dispatch redteam subcommands."""
    if args.rt_action == "status":
        return _rt_status(args)
    elif args.rt_action == "generate":
        return _rt_generate(args)
    elif args.rt_action == "checklist":
        return _rt_checklist(args)
    print("Subcommands: status, generate, checklist")
    return 2


def _rt_status(args) -> int:
    """Show engagement state and available capabilities for the target."""
    from redteam.capabilities import detect_target_type

    caps = load_capabilities()
    target = getattr(args, "target", "") or ""
    ttype = detect_target_type(target)
    available = resolve_for_target(caps, ttype)

    print(_REDTEAM_BANNER)
    print(f"  Target: {target or '(not set)'}")
    print(f"  Type:   {ttype}\n")

    gated = [c for c in available if c.gated]
    non_gated = [c for c in available if not c.gated]
    print(f"  Available: {len(non_gated)} non-gated, {len(gated)} gated (need token)\n")

    for layer_name, layer_range, phase_label in [
        ("Recon (layers 0-1)", [0, 1], "recon"),
        ("Probe (layers 2-7)", [2, 3, 4, 5, 6, 7], "probe"),
        ("Exploit (layer 8)", [8], "exploit"),
        ("Post-Exploit (layer 9)", [9], "post_exploit"),
    ]:
        seg = [c for c in available if any(la in layer_range for la in c.layers)]
        if not seg:
            continue
        print(f"  [{phase_label.upper()}] {layer_name}")
        for c in seg:
            gate_mark = " [GATED]" if c.gated else ""
            print(f"    - {c.label}{gate_mark}")
        print()
    return 0


def _rt_generate(args) -> int:
    """Generate methodology. Kernel-enforced authorization."""
    from redteam.capabilities import detect_target_type

    caps = load_capabilities()
    target = getattr(args, "target", "") or ""
    target_type = detect_target_type(target)
    phase = getattr(args, "phase", "probe")

    try:
        key = config.signing_key()
    except RuntimeError as e:
        print(f"  refused: {e}")
        return 2

    eng = config.load_engagement(_DEFAULT_ENGAGE)
    if not getattr(eng, "open", True):
        print("  refused: engagement is closed or missing.")
        return 2

    from orchestrator.policy import Orchestrator

    orch = Orchestrator(key)
    orch.start_engagement(eng)

    if phase in ("exploit", "post_exploit"):
        # Keep the CLI fail-closed for gated phases. The library API enforces
        # the single-use approval token, but CLI token minting and
        # serialization land in a follow-up. Until then, refuse rather than
        # emit gated content from a token that cannot yet be verified.
        print(
            "  refused: exploit/post_exploit require a single-use approval "
            "token; CLI token minting lands in a follow-up. Use the library "
            "API with a signed ApprovalToken for now."
        )
        return 2

    cap_ids = None
    raw = getattr(args, "capabilities", None)
    if raw:
        cap_ids = raw.split(",")
    if not cap_ids:
        available = resolve_for_target(caps, target_type)
        cap_ids = [c.id for c in available if not c.gated]

    gen = MethodologyGenerator(caps)
    request = GenerateRequest(
        target=target, target_type=target_type, phase=phase,
        capabilities=cap_ids, engagement_id=eng.id,
        approval_token=None, orchestrator=orch,
    )

    try:
        result = gen.generate(request)
    except PermissionError as e:
        print(f"  refused: {e}")
        return 2

    try:
        rk = config.result_key()
        store = ResultStore(_RESULTS_ROOT, eng.id, rk, actor="redteam:generate")
        finding = {
            "finding_id": f"redteam-{phase}-{target[:32]}",
            "type": f"redteam_{phase}_methodology",
            "target": target, "phase": phase,
            "content": result.content,
            "capabilities": (cap_ids or [])[:10],
        }
        finding_id = store.put_finding(finding)
        result.finding_id = finding_id
        result.warnings.append(f"Persisted: {finding_id}")
    except Exception as e:
        result.warnings.append(f"Store unavailable: {e} (content not persisted)")

    print(_REDTEAM_BANNER)
    print(result.content)
    for w in result.warnings:
        if w != "Authorization: ***":
            print(f"  [{w}]")
    print(f"\n  Finding ID: {result.finding_id or '(not persisted)'}")
    print(f"  Engagement: {eng.id}")
    return 0


def _rt_checklist(args) -> int:
    """Generate a pre-flight checklist."""
    try:
        key = config.signing_key()
    except RuntimeError as e:
        print(f"  refused: {e}")
        return 2

    from orchestrator.policy import Orchestrator

    try:
        eng = config.load_engagement(_DEFAULT_ENGAGE)
        Orchestrator(key).start_engagement(eng)
    except Exception as e:
        print(f"  refused: {e}")
        return 2

    gen = ChecklistGenerator()
    checklist = gen.generate(
        target=getattr(args, "target", "") or "",
        phase=getattr(args, "rt_phase", "recon"),
        engagement_id=eng.id,
        authorized_by=eng.authorized_by,
    )

    try:
        rk = config.result_key()
        store = ResultStore(_RESULTS_ROOT, eng.id, rk, actor="redteam:checklist")
        finding = {
            "finding_id": f"checklist-{checklist.checklist_id}",
            "type": "redteam_preflight_checklist",
            "target": checklist.target, "phase": checklist.phase,
            "content": checklist.content,
        }
        store.put_finding(finding)
        print(f"  Saved to engagement {eng.id}")
    except Exception as e:
        print(f"  (store unavailable: {e})")

    print(checklist.content)
    return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wraith", description="Full-spectrum offensive security platform")
    parser.add_argument("--version", action="version", version=f"WRAITH v{__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a target")
    p_scan.add_argument("target")
    p_scan.add_argument("--track", choices=["web", "api", "network", "cloud", "sast", "agentic", "all"], default="all")
    p_scan.add_argument("--dry-run", action="store_true", help="authorize only, no engine execution")
    p_scan.add_argument("--scope", help="path to scope file (default config/scope.yaml)")
    p_scan.add_argument("--engagement-file", dest="engagement_file", help="engagement record file")
    p_scan.add_argument("--report", help="write findings to this JSON path")
    p_scan.add_argument("--timeout", type=float, default=300.0, help="per-engine timeout in seconds")
    p_scan.add_argument("--max-parallel", dest="max_parallel", type=int, default=3, help="max concurrent engines")
    p_scan.set_defaults(func=cmd_scan)

    p_scope = sub.add_parser("scope", help="manage target scope allowlist")
    p_scope.add_argument("action", choices=["add", "list", "rm"])
    p_scope.add_argument("target", nargs="?")
    p_scope.add_argument("--scope", help="path to scope file (default config/scope.yaml)")
    p_scope.set_defaults(func=cmd_scope)

    p_engage = sub.add_parser("engage", help="manage engagement records")
    p_engage.add_argument("action", choices=["start", "close"])
    p_engage.add_argument("--by", help="authorizing operator (required for start)")
    p_engage.add_argument("--hours", type=float, default=8.0, help="engagement lifetime in hours")
    p_engage.add_argument("--scope", help="path to scope file (default config/scope.yaml)")
    p_engage.add_argument("--engagement-file", dest="engagement_file", help="path to engagement file")
    p_engage.set_defaults(func=cmd_engage)

    p_kill = sub.add_parser("kill", help="emergency stop all engines")
    p_kill.add_argument("--reset", action="store_true", help="clear the kill-switch")
    p_kill.set_defaults(func=cmd_kill)

    p_report = sub.add_parser("report", help="summarize or export an engagement's encrypted results")
    p_report.add_argument("engagement", help="engagement id (the results are stored under results/<id>/)")
    p_report.add_argument("--export", help="decrypt findings to this JSON path")
    p_report.add_argument("--actor", help="who is running the report (recorded in the audit log)")
    p_report.set_defaults(func=cmd_report)

    p_engine = sub.add_parser("engine", help="list, check, or run an engine adapter")
    p_engine.add_argument("action", choices=["list", "check", "run"])
    p_engine.add_argument("name", nargs="?", help="engine name (for check/run)")
    p_engine.add_argument("target", nargs="?", help="target to scan (for run)")
    p_engine.add_argument("--store", help="engagement id to store OK findings under")
    p_engine.add_argument("--timeout", type=float, default=300.0, help="engine timeout in seconds")
    p_engine.add_argument("--llm", action="store_true", help="enable LLM augmentation (default off)")
    p_engine.set_defaults(func=cmd_engine)

    p_rt = sub.add_parser("redteam", help="Red Team Annex: methodology generator with guardrails")
    p_rt.add_argument("rt_action", choices=["status", "generate", "checklist"])
    p_rt.add_argument("--target", help="target URL/IP/domain/path")
    p_rt.add_argument("--phase", choices=["recon", "probe", "exploit", "post_exploit"], default="probe",
                      help="methodology phase for generate")
    p_rt.add_argument("--capabilities", help="comma-separated capability ids (default: auto-select)")
    p_rt.add_argument("--engagement", help="engagement file path (for exploit token)")
    p_rt.add_argument("--token", help="single-use approval token signature (for exploit/post_exploit)")
    p_rt.add_argument("--rt-phase", choices=["recon", "probe"], default="recon",
                      help="phase for checklist")
    p_rt.set_defaults(func=cmd_redteam)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
