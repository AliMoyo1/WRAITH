"""WRAITH authority service: hosted, multi-tenant identity and entitlement issuer.

Phase 2 of docs/entitlement-rbac-subscription.md, scoped in
docs/authority-service-scope.md. Sub-phase 1 is the skeleton: the FastAPI app, the
SQLAlchemy storage base, and the tenant-scoped data-access layer. Login, MFA, API
keys, and grant issuance land in later sub-phases.
"""

from __future__ import annotations

from .app import create_app

__all__ = ["create_app"]
