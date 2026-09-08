"""Configuration loading for the WRAITH CLI.

The orchestrator core is pure standard library. This layer reads and writes the
scope and engagement files (YAML when PyYAML is available, JSON otherwise) and
resolves the HMAC signing key from the operator environment.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from orchestrator import Engagement, Scope, ScopeList

try:  # optional dependency; JSON always works
    import yaml  # type: ignore
    _HAVE_YAML = True
except Exception:  # pragma: no cover - exercised only without PyYAML
    _HAVE_YAML = False

SIGNING_KEY_ENV = "WRAITH_SIGNING_KEY"


def _load_mapping(path: Path) -> dict[str, Any]:
    # utf-8-sig tolerates a byte-order mark, which Windows editors often add.
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix in (".yaml", ".yml") and _HAVE_YAML:
        return yaml.safe_load(text) or {}
    if path.suffix == ".json":
        return json.loads(text or "{}")
    # Unknown suffix: try YAML then JSON.
    if _HAVE_YAML:
        return yaml.safe_load(text) or {}
    return json.loads(text or "{}")


def _dump_mapping(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix in (".yaml", ".yml") and _HAVE_YAML:
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    else:
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _scope_list(raw: dict[str, Any] | None) -> ScopeList:
    raw = raw or {}
    return ScopeList(
        cidrs=list(raw.get("cidrs", []) or []),
        domains=list(raw.get("domains", []) or []),
        urls=list(raw.get("urls", []) or []),
        repo_paths=list(raw.get("repo_paths", []) or []),
    )


def load_scope(path: str | Path) -> Scope:
    data = _load_mapping(Path(path))
    node = data.get("scope", data) or {}
    return Scope(
        allow=_scope_list(node.get("allowlist")),
        block=_scope_list(node.get("blocklist")),
        enabled=bool(node.get("enabled", False)),
        allow_metadata=bool(node.get("allow_metadata", False)),
        block_private=bool(node.get("block_private", False)),
    )


def save_scope(path: str | Path, scope: Scope) -> None:
    data = {
        "scope": {
            "enabled": scope.enabled,
            "allow_metadata": scope.allow_metadata,
            "block_private": scope.block_private,
            "allowlist": {
                "cidrs": scope.allow.cidrs,
                "domains": scope.allow.domains,
                "urls": scope.allow.urls,
                "repo_paths": scope.allow.repo_paths,
            },
            "blocklist": {
                "cidrs": scope.block.cidrs,
                "domains": scope.block.domains,
                "urls": scope.block.urls,
                "repo_paths": scope.block.repo_paths,
            },
        }
    }
    _dump_mapping(Path(path), data)


def load_engagement(path: str | Path) -> Engagement:
    data = _load_mapping(Path(path))
    node = data.get("engagement", data)
    return Engagement(
        id=node["id"],
        authorized_by=node.get("authorized_by", ""),
        approved_at=node.get("approved_at", ""),
        expires_at=node.get("expires_at", ""),
        scope=load_scope(path) if node.get("scope") is None else _scope_from_node(node["scope"]),
        open=bool(node.get("open", True)),
        signature=node.get("signature"),
    )


def _scope_from_node(node: dict[str, Any]) -> Scope:
    return Scope(
        allow=_scope_list(node.get("allowlist")),
        block=_scope_list(node.get("blocklist")),
        enabled=bool(node.get("enabled", False)),
        allow_metadata=bool(node.get("allow_metadata", False)),
        block_private=bool(node.get("block_private", False)),
    )


def signing_key() -> bytes:
    """Return the operator HMAC key from the environment, or raise.

    There is deliberately no default key: unsigned or default-signed engagements
    would defeat the authorization model.
    """
    raw = os.environ.get(SIGNING_KEY_ENV)
    if not raw or not raw.strip():
        raise RuntimeError(
            f"{SIGNING_KEY_ENV} is not set. Export an operator signing key before "
            "starting or verifying an engagement."
        )
    return raw.encode("utf-8")
