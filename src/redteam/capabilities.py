"""Load the annex routing table. Maps onto the canonical taxonomy."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml

    _HAVE_YAML = True
except ImportError:
    _HAVE_YAML = False


_DEFAULT_PATH = Path(__file__).resolve().parents[2] / "config" / "redteam_capabilities.yaml"


@dataclass
class Capability:
    id: str = ""
    label: str = ""
    detection_domains: list[str] = field(default_factory=list)
    layers: list[int] = field(default_factory=list)
    target_types: list[str] = field(default_factory=lambda: ["generic"])
    tools: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    interlinks: list[str] = field(default_factory=list)
    gated: bool = False
    description: str = ""


@dataclass
class Capabilities:
    capabilities: dict[str, Capability] = field(default_factory=dict)
    tools: dict[str, dict] = field(default_factory=dict)
    target_defaults: dict[str, list[str]] = field(default_factory=dict)
    presentation: dict[str, Any] = field(default_factory=dict)
    version: str = ""

    def get(self, cap_id: str) -> Capability | None:
        return self.capabilities.get(cap_id)

    def for_target(self, target_type: str) -> list[Capability]:
        cap_ids = self.target_defaults.get(target_type, [])
        return [self.capabilities[cid] for cid in cap_ids if cid in self.capabilities]

    def gated_capabilities(self) -> list[Capability]:
        return [c for c in self.capabilities.values() if c.gated]


def _load_mapping(path: Path) -> dict[str, Any]:
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix in (".yaml", ".yml") and _HAVE_YAML:
        return yaml.safe_load(text) or {}
    import json

    return json.loads(text or "{}")


def load_capabilities(path: str | Path | None = None) -> Capabilities:
    """Load the routing table from a YAML/JSON file."""
    path = Path(path) if path else _DEFAULT_PATH
    if not path.exists():
        raise FileNotFoundError(f"capabilities file not found: {path}")
    data = _load_mapping(path)
    caps = Capabilities()
    caps.version = data.get("version", "")
    caps.presentation = dict(data.get("presentation", {}))

    for cdata in data.get("capabilities", []):
        caps.capabilities[cdata["id"]] = Capability(
            id=cdata["id"],
            label=cdata["label"],
            detection_domains=cdata.get("detection_domains", []),
            layers=cdata.get("layers", []),
            target_types=cdata.get("target_types", ["generic"]),
            tools=cdata.get("tools", []),
            prerequisites=cdata.get("prerequisites", []),
            interlinks=cdata.get("interlinks", []),
            gated=bool(cdata.get("gated", False)),
            description=cdata.get("description", ""),
        )

    caps.tools = dict(data.get("tools", {}))
    for ttype, cids in (data.get("target_type_defaults", {})).items():
        caps.target_defaults[ttype] = list(cids.get("auto_capabilities", []))
    return caps


def resolve_for_target(caps: Capabilities, target_type: str) -> list[Capability]:
    return caps.for_target(target_type)


def detect_target_type(target: str) -> str:
    """Classify a target string into a type for capability resolution."""
    t = target.strip()
    if not t:
        return "generic"
    if "://" in t:
        return "api" if "api" in t.lower() else "url"
    try:
        import ipaddress

        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        pass
    try:
        import ipaddress

        ipaddress.ip_network(t, strict=False)
        return "ip"
    except ValueError:
        pass
    if t.startswith(("/", "~", ".")) or (len(t) >= 3 and t[1] == ":"):
        return "repo_path"
    if "." in t and not t.endswith("."):
        return "domain"
    return "generic"