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

import hmac
import json
import uuid
from collections.abc import Callable
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session, sessionmaker

from adapters import EngineAdapter
from entitlement import CapabilityClass, CapabilityGrant, decode_grant
from evidence import signing_key_optional
from store import ResultStore

from . import repository
from .config import database_url
from .config import engines_dir as _default_engines_dir
from .config import entitlement_public_key as _default_entitlement_public_key
from .config import platform_key as _default_platform_key
from .config import result_key as _default_result_key
from .config import results_root as _default_results_root
from .config import signing_key as _default_signing_key
from .db import create_all, make_engine, make_session_factory
from .engagements import build_engagement, engagement_from_row, scope_from_spec
from .tokens import TokenError, consume_approval_token
from .worker import (
    BackgroundExecutor,
    CubeSandbox,
    EvidenceContext,
    Executor,
    Sandbox,
    default_adapters,
    run_scan,
)


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


class ScanCreate(BaseModel):
    engagement_id: str
    target: str
    track: str
    token: dict | None = None  # required for a gated (offensive) track


# Track -> entitlement capability class.
_TRACK_CLASS = {"sast": "control_plane_scan", "exploit": "redteam_exploit"}
# Gated (consequential) track -> the approval-token action it requires.
_GATED_TRACKS = {"exploit": "exploit"}


class KillRequest(BaseModel):
    reset: bool = False


def _platform_key_ok(provided: str, expected: bytes) -> bool:
    return bool(provided) and hmac.compare_digest(provided.encode("utf-8"), expected)


def create_app(
    session_factory: sessionmaker[Session] | None = None,
    entitlement_public_key: bytes | None = None,
    signing_key: bytes | None = None,
    result_key: bytes | None = None,
    result_root: str | Path | None = None,
    executor: Executor | None = None,
    adapters_for: Callable[[str], list[EngineAdapter]] | None = None,
    platform_key: bytes | None = None,
    sandbox: Sandbox | None = None,
    evidence_key: bytes | None = None,
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
    rkey = result_key if result_key is not None else _default_result_key()
    rroot = Path(result_root) if result_root is not None else Path(_default_results_root())
    scan_executor: Executor = executor if executor is not None else BackgroundExecutor()
    build_adapters = adapters_for or (
        lambda track: default_adapters(track, _default_engines_dir())
    )
    plat_key = platform_key if platform_key is not None else _default_platform_key()
    scan_sandbox = sandbox if sandbox is not None else CubeSandbox()
    # Evidence production is optional: enabled when a signing key is configured.
    ev_key = evidence_key if evidence_key is not None else signing_key_optional()

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

    @app.post("/v1/scans")
    def scan_create(
        body: ScanCreate, authorization: str = Header(default="")
    ) -> dict[str, object]:
        grant = _grant_from_header(authorization, pub)
        # Entitlement gate: the capability class for the track (defensive only now).
        capability = _TRACK_CLASS.get(body.track)
        if capability is None:
            raise HTTPException(status_code=400, detail=f"unsupported track: {body.track}")
        _require_class(grant, capability)
        with session_factory() as session:
            if repository.is_killed(session, grant.tenant_id):
                raise HTTPException(status_code=503, detail="kill-switch engaged")
            row = repository.get_engagement(session, grant.tenant_id, body.engagement_id)
            if row is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            # Engagement gate: the kernel's own validity check plus target-in-scope.
            engagement = engagement_from_row(row)
            ok, reason = engagement.is_valid(sign_key)
            if not ok:
                raise HTTPException(status_code=403, detail=f"engagement invalid: {reason}")
            if not engagement.scope.allows(body.target):
                raise HTTPException(status_code=403, detail="target not in engagement scope")
            # Captured now for the evidence bundle the worker signs after the scan.
            engagement_summary = {
                "id": engagement.id,
                "authorized_by": engagement.authorized_by,
                "approved_at": engagement.approved_at,
                "expires_at": engagement.expires_at,
                "scope_fingerprint": engagement.scope.fingerprint(),
            }
            entitlement_summary = {
                "tenant_id": grant.tenant_id,
                "principal_id": grant.principal_id,
                "roles": grant.roles,
                "tier": grant.tier,
                "capabilities": grant.capabilities,
            }
            # Token gate: a gated (offensive) track additionally requires a valid,
            # single-use, target-bound approval token, consumed durably here.
            action = _GATED_TRACKS.get(body.track)
            if action is not None:
                if not body.token:
                    raise HTTPException(
                        status_code=403, detail="gated track requires an approval token"
                    )
                try:
                    consume_approval_token(
                        session, grant.tenant_id, body.token, sign_key,
                        body.engagement_id, action, body.target,
                    )
                except TokenError as exc:
                    raise HTTPException(status_code=403, detail=str(exc)) from exc
            scan = repository.create_scan(
                session,
                grant.tenant_id,
                target=body.target,
                track=body.track,
                engagement_id=body.engagement_id,
                status="queued",
            )
            scan_id = scan.id
        # Enqueue off the request thread; the executor runs it (inline in tests).
        tenant_id = grant.tenant_id
        target = body.target
        adapters = build_adapters(body.track)
        # Offensive (gated) tracks run inside the sandbox; defensive tracks run directly.
        run_sandbox = scan_sandbox if body.track in _GATED_TRACKS else None
        evidence = (
            EvidenceContext(ev_key, engagement_summary, entitlement_summary)
            if ev_key is not None
            else None
        )
        scan_executor.submit(
            lambda: run_scan(
                session_factory, rroot, rkey, adapters, tenant_id, scan_id, target,
                sandbox=run_sandbox, evidence=evidence,
            )
        )
        return {"id": scan_id, "status": "queued"}

    @app.get("/v1/scans/{scan_id}")
    def scan_get(scan_id: str, authorization: str = Header(default="")) -> dict[str, object]:
        grant = _grant_from_header(authorization, pub)
        _require_class(grant, CapabilityClass.CONTROL_PLANE_READ.value)
        with session_factory() as session:
            scan = repository.get_scan(session, grant.tenant_id, scan_id)
            if scan is None:
                raise HTTPException(status_code=404, detail="scan not found")
            meta: dict[str, object] = {
                "id": scan.id,
                "status": scan.status,
                "target": scan.target,
                "track": scan.track,
                "engagement_id": scan.engagement_id,
                "created_at": scan.created_at,
                "finished_at": scan.finished_at,
            }
        # Findings live in the per-scan encrypted store (isolated by scan id + tenant).
        store = ResultStore(rroot, scan_id, rkey, actor=f"runner:{grant.tenant_id}")
        meta["findings"] = [store.get_finding(fid) for fid in store.list_findings()]
        return meta

    @app.get("/v1/scans/{scan_id}/evidence")
    def scan_evidence(scan_id: str, authorization: str = Header(default="")) -> dict[str, object]:
        # The signed evidence bundle for a completed scan, verifiable with the
        # evidence public key alone. Tenant-scoped by the scan lookup.
        grant = _grant_from_header(authorization, pub)
        _require_class(grant, CapabilityClass.CONTROL_PLANE_READ.value)
        with session_factory() as session:
            if repository.get_scan(session, grant.tenant_id, scan_id) is None:
                raise HTTPException(status_code=404, detail="scan not found")
        store = ResultStore(rroot, scan_id, rkey, actor=f"runner:{grant.tenant_id}")
        bundle = store.get_bundle()
        if bundle is None:
            raise HTTPException(status_code=404, detail="no evidence bundle for this scan")
        return bundle

    @app.post("/v1/kill")
    def kill_tenant(
        body: KillRequest, authorization: str = Header(default="")
    ) -> dict[str, object]:
        # Per-tenant emergency stop, on the caller's own tenant only.
        grant = _grant_from_header(authorization, pub)
        _require_class(grant, "control_plane_scan")
        with session_factory() as session:
            if body.reset:
                repository.clear_kill(session, grant.tenant_id)
            else:
                repository.engage_kill(session, grant.tenant_id)
            killed = repository.is_killed(session, grant.tenant_id)
        return {"scope": "tenant", "tenant_id": grant.tenant_id, "killed": killed}

    @app.post("/v1/admin/kill")
    def kill_global(
        body: KillRequest, x_platform_key: str = Header(default="")
    ) -> dict[str, object]:
        # Platform-operator emergency stop, out of band from tenant entitlement so
        # one tenant can never halt the whole platform.
        if not _platform_key_ok(x_platform_key, plat_key):
            raise HTTPException(status_code=401, detail="invalid platform key")
        with session_factory() as session:
            if body.reset:
                repository.clear_kill(session, "global")
            else:
                repository.engage_kill(session, "global")
            killed = repository.is_killed(session, "global")
        return {"scope": "global", "killed": killed}

    return app
