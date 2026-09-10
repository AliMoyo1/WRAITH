"""WRAITH Runner service: server-side, per-tenant engine execution behind the
entitlement and engagement gates.

This package is a separate service from the authority. It depends only on the
shared ``entitlement`` library and the grant PUBLIC key; it never imports from
``authority`` and never holds the signing secret. See
docs/server-side-execution-scope.md.
"""

from __future__ import annotations

from .app import create_app

__all__ = ["create_app"]
