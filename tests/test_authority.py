"""Tests for the authority service skeleton: health check and tenant isolation."""

from __future__ import annotations

import pytest


@pytest.fixture
def session(tmp_path):
    from authority.db import create_all, make_engine, make_session_factory

    engine = make_engine(f"sqlite:///{tmp_path / 'authority.db'}")
    create_all(engine)
    factory = make_session_factory(engine)
    s = factory()
    try:
        yield s
    finally:
        s.close()


def test_healthz(tmp_path):
    from fastapi.testclient import TestClient

    from authority import create_app
    from authority.db import create_all, make_engine, make_session_factory

    engine = make_engine(f"sqlite:///{tmp_path / 'health.db'}")
    create_all(engine)
    app = create_app(make_session_factory(engine))
    client = TestClient(app)

    resp = client.get("/v1/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_tenant_isolation(session):
    from authority.repository import create_principal, create_tenant, list_principals

    a = create_tenant(session, "Tenant A")
    b = create_tenant(session, "Tenant B")
    create_principal(session, a.id, "alice@a.example")
    create_principal(session, b.id, "bob@b.example")

    a_emails = [p.email for p in list_principals(session, a.id)]
    b_emails = [p.email for p in list_principals(session, b.id)]

    assert a_emails == ["alice@a.example"]
    assert b_emails == ["bob@b.example"]  # tenant A's principal never leaks into B
