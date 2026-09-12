"""WRAITH Agent Bill of Materials.

A signable inventory of an AI agent's model, tools, data sources, MCP servers, and
permissions, with a risk summary of the agentic attack surface. See bom.py.
"""

from __future__ import annotations

from .bom import AgentBOM, build_bom, verify_bom

__all__ = ["AgentBOM", "build_bom", "verify_bom"]
