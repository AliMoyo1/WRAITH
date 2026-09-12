"""Agent Bill of Materials (Agent BOM).

A portable, signable inventory of what makes up an AI agent: its model, tools, data
sources, MCP servers, and permissions, plus a risk summary that surfaces the agentic
attack surface (state-changing tools, external data sources, MCP integrations, and
outbound network). Signed with Ed25519 so a consumer verifies it with the public key
alone, the same way an evidence bundle is verified.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime

from entitlement import sign_bytes, verify_bytes

_VERSION = 1
_STATE_CHANGING = frozenset({"write", "execute"})


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _content_digest(components: list[dict]) -> str:
    return hashlib.sha256(_canonical({"components": components})).hexdigest()


def _components(descriptor: dict) -> list[dict]:
    out: list[dict] = []
    for tool in descriptor.get("tools", []) or []:
        out.append({
            "type": "tool",
            "name": str(tool.get("name", "unknown")),
            "effects": str(tool.get("effects", "unknown")),
        })
    for source in descriptor.get("data_sources", []) or []:
        out.append({
            "type": "data_source",
            "name": str(source.get("name", "unknown")),
            "external": bool(source.get("external", False)),
        })
    for server in descriptor.get("mcp_servers", []) or []:
        out.append({
            "type": "mcp_server",
            "name": str(server.get("name", "unknown")),
            "url": str(server.get("url", "")),
        })
    for perm in descriptor.get("permissions", []) or []:
        out.append({"type": "permission", "name": str(perm)})
    return out


def _summary(components: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for component in components:
        counts[component["type"]] = counts.get(component["type"], 0) + 1
    state_changing = [
        c["name"] for c in components
        if c["type"] == "tool" and c.get("effects") in _STATE_CHANGING
    ]
    external = [c["name"] for c in components if c["type"] == "data_source" and c.get("external")]
    mcp = [c["name"] for c in components if c["type"] == "mcp_server"]
    outbound = any(
        c["type"] == "permission" and ("net" in c["name"].lower() or "outbound" in c["name"].lower())
        for c in components
    )
    return {
        "counts": counts,
        "risk_flags": {
            "state_changing_tools": sorted(state_changing),
            "external_data_sources": sorted(external),
            "mcp_servers": sorted(mcp),
            "outbound_network": outbound,
        },
    }


@dataclass
class AgentBOM:
    """A signed inventory of an agent's makeup. The signature covers the whole
    payload and content_digest pins the components, so tampering is detectable."""

    agent: str
    model: str | None
    components: list[dict]
    summary: dict
    content_digest: str
    created_at: str
    version: int = _VERSION
    signature: str | None = None

    def _payload(self) -> dict:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "agent": self.agent,
            "model": self.model,
            "components": self.components,
            "summary": self.summary,
            "content_digest": self.content_digest,
        }

    def sign(self, private_key: bytes) -> AgentBOM:
        self.signature = sign_bytes(private_key, _canonical(self._payload()))
        return self

    def verify(self, public_key: bytes) -> bool:
        if not self.signature:
            return False
        if _content_digest(self.components) != self.content_digest:
            return False
        return verify_bytes(public_key, self.signature, _canonical(self._payload()))

    def to_dict(self) -> dict:
        return {**self._payload(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: dict) -> AgentBOM:
        return cls(
            agent=data.get("agent", ""),
            model=data.get("model"),
            components=list(data.get("components", [])),
            summary=data.get("summary", {}),
            content_digest=data["content_digest"],
            created_at=data.get("created_at", ""),
            version=int(data.get("version", _VERSION)),
            signature=data.get("signature"),
        )


def build_bom(descriptor: dict) -> AgentBOM:
    """Assemble an unsigned Agent BOM from an agent descriptor."""
    components = _components(descriptor)
    return AgentBOM(
        agent=str(descriptor.get("name", "")),
        model=str(descriptor["model"]) if descriptor.get("model") else None,
        components=components,
        summary=_summary(components),
        content_digest=_content_digest(components),
        created_at=datetime.now(UTC).isoformat(),
    )


def verify_bom(data: dict, public_key: bytes) -> tuple[bool, str]:
    """Standalone verifier: check a serialized Agent BOM's digest and signature."""
    try:
        bom = AgentBOM.from_dict(data)
    except (KeyError, TypeError, ValueError) as exc:
        return False, f"malformed bom: {exc}"
    if not bom.signature:
        return False, "bom is not signed"
    if _content_digest(bom.components) != bom.content_digest:
        return False, "content digest does not match components"
    if not verify_bytes(public_key, bom.signature, _canonical(bom._payload())):
        return False, "signature invalid"
    return True, "ok"
