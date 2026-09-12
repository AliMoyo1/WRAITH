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
import os
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
from orchestrator import (  # noqa: E402
    ApprovalToken,
    Engagement,
    Orchestrator,
    Scope,
    Track,
    now_utc,
)
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
# Engine -> analysis track used by the execution gate, so a single engine run is
# authorized under the track that matches the engine (parity with scan).
_TRACK_FOR_ENGINE = {
    "skillspector": Track.SAST_AGENTIC,
    "strix": Track.WEB_API,
    "trivy": Track.SAST_AGENTIC,
    "semgrep": Track.SAST_AGENTIC,
}


def _scope_path(args) -> Path:
    return Path(getattr(args, "scope", None) or _DEFAULT_SCOPE)


def _load_scope_or_empty(path: Path) -> Scope:
    if path.exists():
        return config.load_scope(path)
    return Scope()


# track -> engine domains; "all" selects by target kind (static repo vs dynamic host).
_TRACK_DOMAINS = {
    "skillspector": {"sast", "agentic"},
    "strix": {"web", "api", "network", "cloud"},
    "trivy": {"sast"},
    "semgrep": {"sast"},
}
# Domains that operate on a static target (a local repo path) rather than a live host.
_STATIC_DOMAINS = {"sast", "agentic"}

# Engines that make third-party network calls even on a local path scan (they fetch
# rules or vulnerability databases from their vendors). Surfaced by the outbound
# preview so a repo scan is not wrongly described as having no egress.
_ENGINE_NETWORK = {
    "semgrep": "downloads rules from the Semgrep registry (--config auto)",
    "trivy": "downloads vulnerability and check databases",
}


def _adapters_for(track: str, target: str) -> list[str]:
    kind = classify_target(target)
    static_ok = kind == "repo_path"
    dynamic_ok = kind in ("url", "domain", "cidr")
    selected: list[str] = []
    for name, domains in _TRACK_DOMAINS.items():
        if track == "all":
            # Select every engine whose kind matches the target: static engines
            # (repo scanners) for a repo path, dynamic engines for a live host.
            is_static = bool(domains & _STATIC_DOMAINS)
            if (is_static and static_ok) or (not is_static and dynamic_ok):
                selected.append(name)
        elif track in domains:
            selected.append(name)
    return selected


def _authorize_scan(
    args, track: Track = Track.SAST_AGENTIC
) -> tuple[int | None, Engagement | None]:
    """Gate execution. With an engagement, use the kernel; otherwise a scope pre-flight.

    Returns (early_exit_code_or_None, engagement_or_None). ``track`` selects the
    analysis track for the kernel authorization so a caller (for example a single
    engine run) can gate under the track that matches the engine.
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
            orch.require_authorization(track, args.target)  # analysis gate: engagement + scope
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
    if getattr(args, "preview", False):
        return _preview_scan(args)
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
    if _KILL_FLAG.exists():
        print("kill-switch engaged; run 'wraith kill --reset' to clear")
        return 3
    # Parity with scan: no engine runs without the kill-switch clear, the target in
    # scope, and (when present) an open, signed engagement. Closes the path where
    # `engine run` reached the adapter with no authorization at all.
    code, _engagement = _authorize_scan(
        args, track=_TRACK_FOR_ENGINE.get(args.name, Track.SAST_AGENTIC)
    )
    if code is not None:
        return code
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
    elif args.rt_action == "authorize":
        return _rt_authorize(args)
    print("Subcommands: status, generate, checklist, authorize")
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

    token = None
    if phase in ("exploit", "post_exploit"):
        tok_path = getattr(args, "token", None)
        if not tok_path:
            print(
                "  refused: exploit/post_exploit require --token <file>; "
                "mint one with 'wraith redteam authorize'."
            )
            return 2
        try:
            token = config.load_token(tok_path)
        except Exception as e:
            print(f"  refused: cannot load approval token: {e}")
            return 2
        if config.is_token_consumed(token.nonce):
            print("  refused: approval token already used (replay refused).")
            return 2

    cap_ids = None
    raw = getattr(args, "capabilities", None)
    if raw:
        cap_ids = raw.split(",")
    if not cap_ids:
        available = resolve_for_target(caps, target_type)
        cap_ids = [c.id for c in available if not c.gated]
        if token is not None:
            cap_ids += [c.id for c in available if c.gated]

    gen = MethodologyGenerator(caps)
    request = GenerateRequest(
        target=target, target_type=target_type, phase=phase,
        capabilities=cap_ids, engagement_id=eng.id,
        approval_token=token, orchestrator=orch,
    )

    try:
        result = gen.generate(request)
    except PermissionError as e:
        print(f"  refused: {e}")
        return 2

    # The token was validated and consumed in-process by the kernel; persist the
    # nonce so a separate invocation refuses a replay of the same token.
    if token is not None:
        config.mark_token_consumed(token.nonce)

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


def _rt_authorize(args) -> int:
    """Mint a single-use approval token for a gated phase (exploit/post_exploit).

    Requires the operator signing key and an open, valid engagement whose scope
    includes the target. Writes a whole, verifiable token to a file that
    'redteam generate --token <file>' consumes exactly once.
    """
    try:
        key = config.signing_key()
    except RuntimeError as e:
        print(f"  refused: {e}")
        return 2

    target = getattr(args, "target", "") or ""
    if not target:
        print("  refused: --target is required")
        return 2
    action = getattr(args, "action", "exploit")

    try:
        eng = config.load_engagement(getattr(args, "engagement", None) or _DEFAULT_ENGAGE)
        Orchestrator(key).start_engagement(eng)
    except Exception as e:
        print(f"  refused: {e}")
        return 2

    if not eng.scope.allows(target):
        print(f"  refused: {target} is not in the authorized scope")
        return 2

    hours = getattr(args, "hours", 1.0)
    token = ApprovalToken(
        engagement_id=eng.id,
        action=action,
        target=target,
        expires_at=(now_utc() + timedelta(hours=hours)).isoformat(),
    ).sign(key)

    out = Path(getattr(args, "out", None) or (_RESULTS_ROOT / "approval_token.json"))
    config.save_token(out, token)

    print(_REDTEAM_BANNER)
    print(f"  Approval token minted: action={action} target={target}")
    print(f"  Engagement: {eng.id}")
    print(f"  Expires: {token.expires_at}")
    print(f"  Saved: {out}")
    print(f"  Next: wraith redteam generate --phase {action} --target {target} --token {out}")
    return 0


_AUTHORITY_ENV = "WRAITH_AUTHORITY_URL"
_DEFAULT_AUTHORITY = "http://localhost:8000"
_SESSION_PATH = _CONFIG_DIR / "session.json"


def _authority_url(args) -> str:
    return getattr(args, "authority", None) or os.environ.get(_AUTHORITY_ENV) or _DEFAULT_AUTHORITY


def cmd_auth(args) -> int:
    """Log in to the authority and manage the cached grant."""
    if args.auth_action == "login":
        return _auth_login(args)
    if args.auth_action == "whoami":
        return _auth_whoami(args)
    if args.auth_action == "logout":
        return _auth_logout(args)
    print("Subcommands: login, whoami, logout")
    return 2


def _auth_login(args) -> int:
    import getpass

    from client import AuthClient, AuthError, save_session

    if not args.tenant or not args.email:
        print("  --tenant and --email are required")
        return 2
    password = args.password or os.environ.get("WRAITH_PASSWORD") or getpass.getpass("Password: ")
    client = AuthClient(_authority_url(args))
    try:
        session = client.login(args.tenant, args.email, password, code=args.code)
    except AuthError as exc:
        print(f"  login failed: {exc}")
        return 2
    finally:
        client.close()
    save_session(_SESSION_PATH, session)
    print(f"  logged in; grant cached at {_SESSION_PATH}")
    print(f"  expires: {session.get('expires_at')}")
    return 0


def _auth_whoami(args) -> int:
    from client import AuthClient, AuthError, grant_expired, load_session, save_session

    session = load_session(_SESSION_PATH)
    if session is None:
        print("  not logged in; run 'wraith auth login' first")
        return 2
    client = AuthClient(_authority_url(args))
    try:
        if grant_expired(session):
            token = session.get("refresh_token")
            if not token:
                print("  session expired; log in again")
                return 2
            session = client.refresh(token)
            save_session(_SESSION_PATH, session)
        identity = client.me(session["grant"])
    except AuthError as exc:
        print(f"  whoami failed: {exc}")
        return 2
    finally:
        client.close()
    print(f"  principal: {identity.get('principal_id')}  tenant: {identity.get('tenant_id')}")
    print(f"  roles: {', '.join(identity.get('roles', []))}")
    print(f"  tier: {identity.get('tier')}")
    print(f"  capabilities: {', '.join(identity.get('capabilities', []))}")
    return 0


def _auth_logout(args) -> int:
    from client import AuthClient, load_session

    session = load_session(_SESSION_PATH)
    token = session.get("refresh_token") if session else None
    if token:
        # Revoke server-side so the refresh token cannot be reused, then clear local.
        client = AuthClient(_authority_url(args))
        try:
            client.logout(token)
        finally:
            client.close()
    if _SESSION_PATH.exists():
        _SESSION_PATH.unlink()
        print("  logged out; cached session removed")
    else:
        print("  no cached session")
    return 0


_RUNNER_ENV = "WRAITH_RUNNER_URL"
_DEFAULT_RUNNER = "http://localhost:8090"


def _runner_url(args) -> str:
    return getattr(args, "runner", None) or os.environ.get(_RUNNER_ENV) or _DEFAULT_RUNNER


def _load_grant(args) -> str | None:
    """Return the cached grant, refreshing it against the authority if expired."""
    from client import AuthClient, AuthError, grant_expired, load_session, refreshed, save_session

    session = load_session(_SESSION_PATH)
    if session is None:
        print("  not logged in; run 'wraith auth login' first")
        return None
    if grant_expired(session):
        auth = AuthClient(_authority_url(args))
        try:
            session = refreshed(auth, session)
        except AuthError as exc:
            print(f"  session expired and refresh failed: {exc}")
            return None
        finally:
            auth.close()
        save_session(_SESSION_PATH, session)
    grant = session.get("grant")
    return str(grant) if grant else None


def _scope_to_spec(scope) -> dict:
    return {
        "enabled": scope.enabled,
        "allow_metadata": scope.allow_metadata,
        "block_private": scope.block_private,
        "allowlist": {
            "cidrs": scope.allow.cidrs, "domains": scope.allow.domains,
            "urls": scope.allow.urls, "repo_paths": scope.allow.repo_paths,
        },
        "blocklist": {
            "cidrs": scope.block.cidrs, "domains": scope.block.domains,
            "urls": scope.block.urls, "repo_paths": scope.block.repo_paths,
        },
    }


def cmd_runner(args) -> int:
    """Drive the Runner using the cached grant: engagements and scans."""
    from client import RunnerClient, RunnerError

    grant = _load_grant(args)
    if grant is None:
        return 2
    client = RunnerClient(_runner_url(args))
    try:
        if args.runner_action == "engage":
            return _runner_engage(client, grant, args)
        if args.runner_action == "scan":
            return _runner_scan(client, grant, args)
        if args.runner_action == "status":
            return _runner_status(client, grant, args)
        if args.runner_action == "scans":
            return _runner_scans(client, grant, args)
        if args.runner_action == "evidence":
            return _runner_evidence(client, grant, args)
        print("Subcommands: engage, scan, status, scans, evidence")
        return 2
    except RunnerError as exc:
        print(f"  runner error: {exc}")
        return 2
    finally:
        client.close()


def _runner_engage(client, grant: str, args) -> int:
    scope_path = _scope_path(args)
    if not scope_path.exists():
        print(f"  no scope file at {scope_path}; run 'wraith scope add <target>' first")
        return 2
    spec = _scope_to_spec(config.load_scope(scope_path))
    # The approver identity is derived server-side from the verified grant.
    result = client.create_engagement(grant, spec, ttl_minutes=int(args.hours * 60))
    print(f"  engagement {result['id']} (expires {result.get('expires_at')})")
    return 0


def _runner_scan(client, grant: str, args) -> int:
    if not args.engagement_id:
        print("  --engagement <id> is required")
        return 2
    if not args.arg:
        print("  a target is required")
        return 2
    token = config.load_token(args.token).to_dict() if args.token else None
    result = client.create_scan(grant, args.engagement_id, args.arg, args.track, token=token)
    print(f"  scan {result['id']} ({result.get('status')})")
    return 0


def _runner_status(client, grant: str, args) -> int:
    if not args.arg:
        print("  a scan id is required")
        return 2
    scan = client.get_scan(grant, args.arg)
    print(f"  scan {scan['id']}: {scan['status']} ({len(scan.get('findings', []))} finding(s))")
    return 0


def _runner_scans(client, grant: str, args) -> int:
    scans = client.list_scans(grant).get("scans", [])
    if not scans:
        print("  no scans")
        return 0
    for s in scans:
        print(f"  {s['id']}: {s['status']} track={s.get('track')} target={s.get('target')}")
    return 0


def _runner_evidence(client, grant: str, args) -> int:
    import json

    if not args.arg:
        print("  a scan id is required")
        return 2
    bundle = client.get_evidence(grant, args.arg)
    if args.out:
        Path(args.out).write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        print(f"  evidence written to {args.out}; verify with 'wraith evidence verify {args.out}'")
    else:
        print(f"  evidence for {args.arg}: {bundle.get('completeness')}")
    return 0


def cmd_evidence(args) -> int:
    """Verify a signed evidence bundle with the evidence public key."""
    if args.evidence_action == "verify":
        return _evidence_verify(args)
    print("Subcommands: verify")
    return 2


def _evidence_verify(args) -> int:
    import json

    from evidence import public_key, verify_bundle

    if not args.file:
        print("  a bundle file is required")
        return 2
    try:
        data = json.loads(Path(args.file).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        print(f"  cannot read bundle: {exc}")
        return 2
    try:
        pub = public_key()
    except RuntimeError as exc:
        print(f"  {exc}")
        return 2
    ok, reason = verify_bundle(data, pub)
    print(f"  {'VALID' if ok else 'INVALID'}: {reason}")
    return 0 if ok else 2


def _preview_scan(args) -> int:
    """Outbound-data preview: what a scan would send, without running any engine."""
    target = args.target
    kind = classify_target(target)
    print(f"  target: {target}  (kind={kind}, track={args.track})")
    scope_path = _scope_path(args)
    if scope_path.exists():
        scope = config.load_scope(scope_path)
        verdict = "IN SCOPE" if scope.allows(target) else "OUT OF SCOPE"
        print(f"  scope: {verdict} (enabled={scope.enabled})")
    else:
        print(f"  scope: no scope file at {scope_path}")
    if _KILL_FLAG.exists():
        print("  kill-switch: ENGAGED (a real scan would refuse)")
    names = _adapters_for(args.track, target)
    if not names:
        print("  engines: none apply to this target and track")
    for name in names:
        adapter, _err = _build_adapter(name)
        available = adapter is not None and adapter.is_available()[0]
        print(f"  engine {name}: would run ({'available' if available else 'unavailable'})")
    if kind == "repo_path":
        print("  outbound: reads the local path; its contents are not uploaded")
    else:
        print(f"  outbound: the engines above send probes to {target}")
    # Some static engines still make third-party calls even on a local path scan:
    # they download rules or vulnerability databases from their vendors.
    net_engines = [n for n in names if n in _ENGINE_NETWORK]
    for name in net_engines:
        print(f"  network: {name} {_ENGINE_NETWORK[name]}")
    if kind == "repo_path" and net_engines:
        print("  note: those fetches are third-party network calls; run engines offline to avoid them")
    print("  findings: stored locally and encrypted; results are not sent to third parties")
    return 0


def cmd_doctor(args) -> int:
    """Local readiness diagnostic: keys, scope, engagement, kill-switch, engines, session.

    Read-only: it inspects local configuration and never runs an engine or touches the
    network. Exit 0 unless a check is an error.
    """
    checks: list[tuple[str, str, str]] = []

    for env_name, purpose in (
        (config.SIGNING_KEY_ENV, "engagement signing"),
        (config.RESULT_KEY_ENV, "result-store encryption"),
    ):
        ok = bool(os.environ.get(env_name))
        checks.append(("OK" if ok else "WARN", env_name, "set" if ok else f"not set ({purpose})"))

    scope_path = _scope_path(args)
    if not scope_path.exists():
        checks.append(("WARN", "scope", f"no scope file at {scope_path}"))
    else:
        try:
            scope = config.load_scope(scope_path)
        except Exception as exc:  # a diagnostic reports parse failures, never raises
            checks.append(("ERROR", "scope", f"cannot parse {scope_path}: {exc}"))
        else:
            entries = (
                len(scope.allow.domains) + len(scope.allow.cidrs)
                + len(scope.allow.urls) + len(scope.allow.repo_paths)
            )
            if not scope.enabled:
                checks.append(("WARN", "scope", "present but disabled (fail-closed)"))
            elif entries == 0:
                checks.append(("WARN", "scope", "enabled but the allowlist is empty"))
            else:
                checks.append(("OK", "scope", f"enabled, {entries} allowlist entries"))

    engage_path = Path(getattr(args, "engagement_file", None) or _DEFAULT_ENGAGE)
    if not engage_path.exists():
        checks.append(("WARN", "engagement", "none (scans run ephemerally, not persisted)"))
    else:
        try:
            eng = config.load_engagement(engage_path)
        except Exception as exc:
            checks.append(("ERROR", "engagement", f"cannot parse {engage_path}: {exc}"))
        else:
            try:
                key = config.signing_key()
            except RuntimeError:
                checks.append(("WARN", "engagement", "present but WRAITH_SIGNING_KEY unset; cannot verify"))
            else:
                ok, reason = eng.is_valid(key)
                checks.append(("OK" if ok else "ERROR", "engagement", reason))

    checks.append(
        ("WARN", "kill-switch", "ENGAGED (run 'wraith kill --reset')")
        if _KILL_FLAG.exists()
        else ("OK", "kill-switch", "clear")
    )

    for name in sorted(ADAPTERS):
        adapter, err = _build_adapter(name)
        if adapter is None:
            checks.append(("WARN", f"engine:{name}", err or "unavailable"))
        else:
            ok, reason = adapter.is_available()
            checks.append(("OK" if ok else "WARN", f"engine:{name}", reason))

    from client import grant_expired, load_session

    session = load_session(_SESSION_PATH)
    if session is None:
        checks.append(("WARN", "auth", "not logged in (run 'wraith auth login')"))
    else:
        expired = grant_expired(session)
        checks.append(("WARN" if expired else "OK", "auth", "grant expired" if expired else "logged in"))

    marks = {"OK": "ok  ", "WARN": "warn", "ERROR": "ERR "}
    for level, name, detail in checks:
        print(f"  [{marks[level]}] {name}: {detail}")
    errors = sum(1 for level, _, _ in checks if level == "ERROR")
    warnings = sum(1 for level, _, _ in checks if level == "WARN")
    print(f"  summary: {errors} error(s), {warnings} warning(s)")
    return 1 if errors else 0


def cmd_entitlement(args) -> int:
    """Least-privilege analysis over roles and tiers."""
    if args.entitlement_action == "recommend":
        return _entitlement_recommend(args)
    if args.entitlement_action == "graph":
        return _entitlement_graph(args)
    print("Subcommands: recommend, graph")
    return 2


def _entitlement_recommend(args) -> int:
    from entitlement import analyze_grant, minimal_roles_tier

    needed = [c.strip() for c in (args.needed or "").split(",") if c.strip()]
    if not needed:
        print("  supply --needed <comma-separated capability classes>")
        return 2
    if bool(args.roles) != bool(args.tier):
        print("  provide both --roles and --tier to analyze a current grant")
        return 2
    try:
        if args.roles:
            roles = [r.strip() for r in args.roles.split(",") if r.strip()]
            report = analyze_grant(roles, args.tier, needed)
        else:
            rec = minimal_roles_tier(needed)
            report = {
                "needed": sorted(needed),
                "recommended_roles": sorted(r.value for r in rec[0]) if rec else None,
                "recommended_tier": rec[1].value if rec else None,
            }
    except ValueError as exc:
        print(f"  invalid role or tier: {exc}")
        return 2
    for key, value in report.items():
        print(f"  {key}: {value}")
    if report.get("recommended_roles") is None:
        print("  note: some needed classes are not grantable by any role or tier")
    return 0


def _entitlement_graph(args) -> int:
    import json

    from authority_graph import build_authority_graph

    if not args.roles or not args.tier:
        print("  provide --roles <comma-separated> and --tier to graph a principal")
        return 2
    roles = [r.strip() for r in args.roles.split(",") if r.strip()]
    try:
        graph = build_authority_graph(roles, args.tier)
    except ValueError as exc:
        print(f"  invalid role or tier: {exc}")
        return 2
    data = graph.to_dict()
    if args.json:
        text = json.dumps(data, indent=2)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            print(f"  wrote {args.out}")
        else:
            print(text)
        return 0
    reach = data["reachability"]
    print(f"  principal: roles={data['principal']['roles']} tier={data['principal']['tier']}")
    print(f"  held classes: {reach['held_classes']}")
    print(f"  blocked classes: {reach['blocked_classes']}")
    print(f"  reachable tracks: {reach['reachable_tracks']}")
    print(f"  can reach consequential: {reach['can_reach_consequential']}")
    if reach["consequential_classes"]:
        print(f"  consequential still requires single-use token for: {reach['requires_single_use_token']}")
    print("  entitlement gate (principal -> class):")
    for edge in data["edges"]:
        if edge["gate"] == "entitlement" and edge["granted"]:
            print(f"    {edge['dst']}: {edge['reason']}")
    print("  engagement gate (held class -> activity, still gated by):")
    for node in data["nodes"]:
        if node["kind"] == "activity" and node["target_directed"]:
            print(f"    {node['label']}: tracks={node['tracks']} requires {node['conditions']}")
    return 0


def cmd_agentbom(args) -> int:
    """Build or verify an Agent Bill of Materials."""
    if args.agentbom_action == "build":
        return _agentbom_build(args)
    if args.agentbom_action == "verify":
        return _agentbom_verify(args)
    print("Subcommands: build, verify")
    return 2


def _agentbom_build(args) -> int:
    import json

    from agentbom import build_bom
    from evidence import signing_key_optional

    if not args.file:
        print("  a descriptor file is required")
        return 2
    try:
        descriptor = json.loads(Path(args.file).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        print(f"  cannot read descriptor: {exc}")
        return 2
    bom = build_bom(descriptor)
    key = signing_key_optional()
    if key is not None:
        bom.sign(key)
    if args.out:
        Path(args.out).write_text(json.dumps(bom.to_dict(), indent=2), encoding="utf-8")
        print(f"  agent BOM ({'signed' if bom.signature else 'unsigned'}) written to {args.out}")
    else:
        summary = bom.summary
        print(f"  agent: {bom.agent} (model={bom.model})")
        print(f"  components: {summary['counts']}")
        for flag, value in summary["risk_flags"].items():
            print(f"  {flag}: {value}")
    return 0


def _agentbom_verify(args) -> int:
    import json

    from agentbom import verify_bom
    from evidence import public_key

    if not args.file:
        print("  a BOM file is required")
        return 2
    try:
        data = json.loads(Path(args.file).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        print(f"  cannot read bom: {exc}")
        return 2
    try:
        pub = public_key()
    except RuntimeError as exc:
        print(f"  {exc}")
        return 2
    ok, reason = verify_bom(data, pub)
    print(f"  {'VALID' if ok else 'INVALID'}: {reason}")
    return 0 if ok else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wraith", description="Full-spectrum offensive security platform")
    parser.add_argument("--version", action="version", version=f"WRAITH v{__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a target")
    p_scan.add_argument("target")
    p_scan.add_argument("--track", choices=["web", "api", "network", "cloud", "sast", "agentic", "all"], default="all")
    p_scan.add_argument("--dry-run", action="store_true", help="authorize only, no engine execution")
    p_scan.add_argument("--preview", action="store_true", help="preview what the scan would send; run no engines")
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
    p_engine.add_argument("--scope", help="path to scope file (default config/scope.yaml)")
    p_engine.add_argument("--engagement-file", dest="engagement_file", help="engagement record file")
    p_engine.set_defaults(func=cmd_engine)

    p_rt = sub.add_parser("redteam", help="Red Team Annex: methodology generator with guardrails")
    p_rt.add_argument("rt_action", choices=["status", "generate", "checklist", "authorize"])
    p_rt.add_argument("--target", help="target URL/IP/domain/path")
    p_rt.add_argument("--phase", choices=["recon", "probe", "exploit", "post_exploit"], default="probe",
                      help="methodology phase for generate")
    p_rt.add_argument("--capabilities", help="comma-separated capability ids (default: auto-select)")
    p_rt.add_argument("--engagement", help="engagement file path (default config/engagement.json)")
    p_rt.add_argument("--token", help="path to a serialized approval token file (for exploit/post_exploit)")
    p_rt.add_argument("--action", choices=["exploit", "post_exploit"], default="exploit",
                      help="action to authorize (for the authorize subcommand)")
    p_rt.add_argument("--hours", type=float, default=1.0, help="approval token lifetime in hours")
    p_rt.add_argument("--out", help="output path for the minted approval token")
    p_rt.add_argument("--rt-phase", choices=["recon", "probe"], default="recon",
                      help="phase for checklist")
    p_rt.set_defaults(func=cmd_redteam)

    p_auth = sub.add_parser("auth", help="log in to the WRAITH authority and cache a grant")
    p_auth.add_argument("auth_action", choices=["login", "whoami", "logout"])
    p_auth.add_argument("--authority", help="authority base URL (default env WRAITH_AUTHORITY_URL)")
    p_auth.add_argument("--tenant", help="tenant slug (for login)")
    p_auth.add_argument("--email", help="principal email (for login)")
    p_auth.add_argument("--password", help="password (or WRAITH_PASSWORD, or prompt)")
    p_auth.add_argument("--code", help="TOTP code (for MFA-required logins)")
    p_auth.set_defaults(func=cmd_auth)

    p_runner = sub.add_parser("runner", help="drive the Runner: engagements and scans (needs 'auth login')")
    p_runner.add_argument("runner_action", choices=["engage", "scan", "status", "scans", "evidence"])
    p_runner.add_argument("arg", nargs="?", help="scan target (for scan) or scan id (for status/evidence)")
    p_runner.add_argument("--runner", help="Runner base URL (default env WRAITH_RUNNER_URL)")
    p_runner.add_argument("--authority", help="authority base URL (for grant refresh)")
    p_runner.add_argument("--engagement", dest="engagement_id", help="engagement id (for scan)")
    p_runner.add_argument("--track", default="sast", help="scan track (default sast)")
    p_runner.add_argument("--token", help="approval token file (for a gated track)")
    p_runner.add_argument("--scope", help="scope file (for engage; default config/scope.yaml)")
    p_runner.add_argument("--by", help="authorizing operator (for engage)")
    p_runner.add_argument("--hours", type=float, default=8.0, help="engagement lifetime in hours (for engage)")
    p_runner.add_argument("--out", help="write the evidence bundle to this file (for evidence)")
    p_runner.set_defaults(func=cmd_runner)

    p_evidence = sub.add_parser("evidence", help="verify a signed evidence bundle")
    p_evidence.add_argument("evidence_action", choices=["verify"])
    p_evidence.add_argument("file", nargs="?", help="path to the bundle JSON")
    p_evidence.set_defaults(func=cmd_evidence)

    p_doctor = sub.add_parser("doctor", help="check local readiness: keys, scope, engagement, engines")
    p_doctor.add_argument("--scope", help="path to scope file (default config/scope.yaml)")
    p_doctor.add_argument("--engagement-file", dest="engagement_file", help="engagement record file")
    p_doctor.set_defaults(func=cmd_doctor)

    p_ent = sub.add_parser("entitlement", help="least-privilege recommendations and effective-authority graph")
    p_ent.add_argument("entitlement_action", choices=["recommend", "graph"])
    p_ent.add_argument("--needed", help="comma-separated capability classes the principal needs (recommend)")
    p_ent.add_argument("--roles", help="comma-separated roles (recommend: with --tier to analyze; graph: required)")
    p_ent.add_argument("--tier", help="tier (recommend: with --roles; graph: required)")
    p_ent.add_argument("--json", action="store_true", help="emit the full graph as JSON (graph)")
    p_ent.add_argument("--out", help="write JSON graph to this file (graph, with --json)")
    p_ent.set_defaults(func=cmd_entitlement)

    p_bom = sub.add_parser("agentbom", help="build or verify an Agent Bill of Materials")
    p_bom.add_argument("agentbom_action", choices=["build", "verify"])
    p_bom.add_argument("file", nargs="?", help="descriptor JSON (build) or BOM JSON (verify)")
    p_bom.add_argument("--out", help="write the BOM to this file (build)")
    p_bom.set_defaults(func=cmd_agentbom)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
