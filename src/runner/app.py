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

from fastapi import FastAPI, Header, HTTPException
from sqlalchemy.orm import Session, sessionmaker

from entitlement import CapabilityClass, CapabilityGrant, decode_grant

from . import repository
from .config import database_url
from .config import entitlement_public_key as _default_entitlement_public_key
from .db import create_all, make_engine, make_session_factory


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


def create_app(
    session_factory: sessionmaker[Session] | None = None,
    entitlement_public_key: bytes | None = None,
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

    return app
