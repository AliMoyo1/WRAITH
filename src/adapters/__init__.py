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
from .skillspector import SkillSpectorAdapter

# Registry of known adapter names to their classes.
ADAPTERS = {SkillSpectorAdapter.name: SkillSpectorAdapter}

__all__ = [
    "ADAPTERS",
    "ADAPTER_CONTRACT_VERSION",
    "AdapterRequest",
    "AdapterResult",
    "EngineAdapter",
    "SkillSpectorAdapter",
    "SubprocessResult",
    "run_subprocess",
]
