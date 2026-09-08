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
import sys
import uuid
from datetime import timedelta
from pathlib import Path

# Allow running as a plain script: put the src/ root on the path.
_SRC = Path(__file__).resolve().parents[1]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import config  # noqa: E402
from orchestrator import Engagement, Scope, now_utc  # noqa: E402
from orchestrator.scope import classify_target  # noqa: E402

__version__ = "2.1"

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_DIR = _REPO_ROOT / "config"
_DEFAULT_SCOPE = _CONFIG_DIR / "scope.yaml"
_DEFAULT_ENGAGE = _CONFIG_DIR / "engagement.json"
_KILL_FLAG = _CONFIG_DIR / ".killed"


def _scope_path(args) -> Path:
    return Path(getattr(args, "scope", None) or _DEFAULT_SCOPE)


def _load_scope_or_empty(path: Path) -> Scope:
    if path.exists():
        return config.load_scope(path)
    return Scope()


def cmd_scan(args) -> int:
    if _KILL_FLAG.exists():
        print("kill-switch engaged; run 'wraith kill --reset' to clear")
        return 3
    path = _scope_path(args)
    if not path.exists():
        print(f"no scope file at {path}; run 'wraith scope add <target>' first")
        return 2
    scope = config.load_scope(path)
    if not scope.enabled:
        print("scope is not enabled (fail closed); set scope.enabled: true after review")
        return 2
    if not scope.allows(args.target):
        print(f"refused: {args.target} is not in the authorized scope")
        return 2
    print(f"in scope: {args.target} (track={args.track})")
    if args.dry_run:
        print("dry-run: no engines invoked")
    else:
        print("[skeleton] engine adapters not yet connected (Phase 1+)")
    return 0


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
    print(f"[skeleton] report for engagement {args.engagement}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wraith", description="Full-spectrum offensive security platform")
    parser.add_argument("--version", action="version", version=f"WRAITH v{__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a target")
    p_scan.add_argument("target")
    p_scan.add_argument("--track", choices=["web", "api", "network", "cloud", "sast", "agentic", "all"], default="all")
    p_scan.add_argument("--dry-run", action="store_true", help="report only, no engine execution")
    p_scan.add_argument("--scope", help="path to scope file (default config/scope.yaml)")
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

    p_report = sub.add_parser("report", help="generate report")
    p_report.add_argument("engagement")
    p_report.set_defaults(func=cmd_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
