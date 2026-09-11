"""WRAITH engine adapters.

Each adapter runs an external engine as an isolated subprocess and returns
findings normalized to schemas/finding.schema.json. See base.EngineAdapter.
"""

from __future__ import annotations

from .base import (
    ADAPTER_CONTRACT_VERSION,
    AdapterRequest,
    AdapterResult,
    EngineAdapter,
    SubprocessResult,
    run_subprocess,
)
from .semgrep import SemgrepAdapter
from .skillspector import SkillSpectorAdapter
from .strix import StrixAdapter
from .trivy import TrivyAdapter

# Registry of known adapter names to their classes.
ADAPTERS = {
    SkillSpectorAdapter.name: SkillSpectorAdapter,
    StrixAdapter.name: StrixAdapter,
    TrivyAdapter.name: TrivyAdapter,
    SemgrepAdapter.name: SemgrepAdapter,
}

__all__ = [
    "ADAPTERS",
    "ADAPTER_CONTRACT_VERSION",
    "AdapterRequest",
    "AdapterResult",
    "EngineAdapter",
    "SemgrepAdapter",
    "SkillSpectorAdapter",
    "StrixAdapter",
    "SubprocessResult",
    "TrivyAdapter",
    "run_subprocess",
]
