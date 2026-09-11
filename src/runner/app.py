"""FastAPI application for the WRAITH Runner service.

The Runner runs the engines server-side, per tenant, behind two gates: the
entitlement gate (this grant may use this capability class) and, in later
sub-phases, the engagement gate (this target, now, under an open signed
engagement). This skeleton (phase 4 sub-phase 2) establishes the service,
tenant-scoped storage, the grant-verification middleware, and the capability-class
check. Engagements, scan execution, the kill-switch, and offensive isolation land
in later sub-phases. See docs/server-side-execution-scope.md.

The Runner holds only the entitlement PUBLIC key: it verifies grants, it never
signs them, and the signing secret never reaches this service.
"""

from __future__ import annotations

import json
import uuid

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session, sessionmaker

from entitlement import CapabilityClass, CapabilityGrant, decode_grant

from . import repository
from .config import database_url
from .config import entitlement_public_key as _default_entitlement_public_key
from .config import signing_key as _default_signing_key
from .db import create_all, make_engine, make_session_factory
from .engagements import build_engagement, engagement_from_row, scope_from_spec


def _grant_from_header(authorization: str, public_key: bytes) -> CapabilityGrant:
    """Decode and verify the bearer grant with the public key. Fail closed.

    Missing, malformed, invalid-signature, or expired all resolve to 401. This is
    the entitlement gate's authentication step; the capability-class check is the
    authorization step (see _require_class).
    """
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer grant")
    token = authorization[len("bearer "):].strip()
    try:
        grant = decode_grant(token)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="malformed grant") from exc
    if not grant.verify(public_key) or grant.is_expired():
        raise HTTPException(status_code=401, detail="invalid or expired grant")
    return grant


def _require_class(grant: CapabilityGrant, capability_class: str) -> None:
    if not grant.allows(capability_class):
        raise HTTPException(status_code=403, detail="insufficient capability")


class EngagementCreate(BaseModel):
    authorized_by: str
    scope: dict
    ttl_minutes: int = 480


def create_app(
    session_factory: sessionmaker[Session] | None = None,
    entitlement_public_key: bytes | None = None,
    signing_key: bytes | None = None,
) -> FastAPI:
    if session_factory is None:
        engine = make_engine(database_url())
        create_all(engine)
        session_factory = make_session_factory(engine)
    pub = (
        entitlement_public_key
        if entitlement_public_key is not None
        else _default_entitlement_public_key()
    )
    sign_key = signing_key if signing_key is not None else _default_signing_key()

    app = FastAPI(title="WRAITH Runner", version="0.1.0")
    app.state.session_factory = session_factory

    @app.get("/v1/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/scans")
    def list_scans(authorization: str = Header(default="")) -> dict[str, object]:
        # Entitlement gate: a valid grant that carries the read capability class.
        grant = _grant_from_header(authorization, pub)
        _require_class(grant, CapabilityClass.CONTROL_PLANE_READ.value)
        # Tenant isolation: the tenant comes from the verified grant, never the
        # client, so a caller only ever sees its own tenant's scans.
        with session_factory() as session:
            rows = [
                {
                    "id": s.id,
                    "engagement_id": s.engagement_id,
                    "target": s.target,
                    "track": s.track,
                    "status": s.status,
                    "created_at": s.created_at,
                }
                for s in repository.list_scans(session, grant.tenant_id)
            ]
        return {"scans": rows}

    @app.post("/v1/engagements")
    def engagement_create(
        body: EngagementCreate, authorization: str = Header(default="")
    ) -> dict[str, object]:
        # Operator capability: authoring an engagement is a scan-initiating action,
        # gated by control_plane_scan (held by Analyst and Operator, not Viewer).
        grant = _grant_from_header(authorization, pub)
        _require_class(grant, CapabilityClass.CONTROL_PLANE_SCAN.value)
        scope = scope_from_spec(body.scope)
        engagement = build_engagement(
            uuid.uuid4().hex, body.authorized_by, scope, body.ttl_minutes, sign_key
        )
        assert engagement.signature is not None  # sign() set it
        with session_factory() as session:
            row = repository.create_engagement(
                session,
                engagement_id=engagement.id,
                tenant_id=grant.tenant_id,
                created_by=engagement.authorized_by,
                scope_json=json.dumps(body.scope),
                approved_at=engagement.approved_at,
                expires_at=engagement.expires_at,
                signature=engagement.signature,
            )
            payload: dict[str, object] = {
                "id": row.id,
                "expires_at": row.expires_at,
                "open": row.open,
            }
        return payload

    @app.get("/v1/engagements/{engagement_id}")
    def engagement_get(
        engagement_id: str, authorization: str = Header(default="")
    ) -> dict[str, object]:
        grant = _grant_from_header(authorization, pub)
        _require_class(grant, CapabilityClass.CONTROL_PLANE_READ.value)
        with session_factory() as session:
            row = repository.get_engagement(session, grant.tenant_id, engagement_id)
            if row is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            # Enforced by the kernel's own Engagement: signature, expiry, open, scope.
            ok, reason = engagement_from_row(row).is_valid(sign_key)
            payload: dict[str, object] = {
                "id": row.id,
                "created_by": row.created_by,
                "approved_at": row.approved_at,
                "expires_at": row.expires_at,
                "open": row.open,
                "valid": ok,
                "reason": reason,
            }
        return payload

    @app.post("/v1/engagements/{engagement_id}/close")
    def engagement_close(
        engagement_id: str, authorization: str = Header(default="")
    ) -> dict[str, object]:
        grant = _grant_from_header(authorization, pub)
        _require_class(grant, CapabilityClass.CONTROL_PLANE_SCAN.value)
        with session_factory() as session:
            row = repository.get_engagement(session, grant.tenant_id, engagement_id)
            if row is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            repository.close_engagement(session, row)
            payload: dict[str, object] = {"id": row.id, "open": row.open}
        return payload

    return app
