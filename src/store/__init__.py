"""WRAITH result store package.

Encrypted, per-engagement storage for findings and evidence, with a
tamper-evident audit log. See WRAITH.md Section 11.5 (Results-Store Sensitivity).
"""

from __future__ import annotations

from .result_store import ResultStore, ResultStoreError

__all__ = ["ResultStore", "ResultStoreError"]
