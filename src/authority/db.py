"""SQLAlchemy engine, session factory, and declarative base for the authority.

Tables are created with ``create_all`` in dev and tests. Production migrations
(Alembic) are deferred until the schema stabilizes in a later sub-phase.
"""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    """Declarative base for all authority models."""


def make_engine(url: str) -> Engine:
    # check_same_thread is relaxed for SQLite so a threaded TestClient can share
    # a file-backed database; it has no effect on other backends.
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, future=True, connect_args=connect_args)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, class_=Session, expire_on_commit=False, future=True)


def create_all(engine: Engine) -> None:
    """Create all tables. Import models first so they register on the metadata."""
    from . import models  # noqa: F401

    Base.metadata.create_all(engine)
