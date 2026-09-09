"""FastAPI application for the WRAITH authority service.

Sub-phase 1 exposes only the public health check. The session factory is stored
on the app for the routes (login, MFA, grant issuance) that arrive in later
sub-phases. Build the app with ``create_app`` and inject a session factory in
tests.
"""

from __future__ import annotations

from fastapi import FastAPI
from sqlalchemy.orm import Session, sessionmaker

from .config import database_url
from .db import create_all, make_engine, make_session_factory


def create_app(session_factory: sessionmaker[Session] | None = None) -> FastAPI:
    if session_factory is None:
        engine = make_engine(database_url())
        create_all(engine)
        session_factory = make_session_factory(engine)

    app = FastAPI(title="WRAITH Authority", version="0.1.0")
    app.state.session_factory = session_factory

    @app.get("/v1/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
