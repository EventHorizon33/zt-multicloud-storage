"""Audit database schema and engine.

The audit log has its own declarative base and its own engine
(``settings.audit_database_url``), separate from the metadata database
(ADR-0006): compromising or rolling back the metadata DB does not rewrite
the audit trail, and a business-transaction rollback cannot remove an audit
record.
"""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import Connection, Engine, Index, Integer, String, Text, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.pool import StaticPool

# Arbitrary constant identifying "the audit chain" for pg_advisory_xact_lock.
PG_ADVISORY_LOCK_KEY = 0x5A54_4155_4449_54  # "ZTAUDIT"


class AuditBase(DeclarativeBase):
    """Declarative base for the audit database only."""


class AuditEventRow(AuditBase):
    __tablename__ = "audit_events"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    ts: Mapped[str] = mapped_column(Text, nullable=False)          # ISO-8601 UTC text, hashed byte-exact
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(40), nullable=True)   # pseudonym, never a raw id
    actor_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resource_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[str] = mapped_column(Text, nullable=False)     # canonical JSON text
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_net: Mapped[str | None] = mapped_column(String(64), nullable=True)  # e.g. "203.0.113.0/24"
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_audit_events_ts", "ts"),
        Index("ix_audit_events_actor", "actor"),
        Index("ix_audit_events_event_type", "event_type"),
        Index("ix_audit_events_resource_id", "resource_id"),
        Index("ix_audit_events_outcome", "outcome"),
        Index("ix_audit_events_severity", "severity"),
        Index("ix_audit_events_request_id", "request_id"),
        Index("ix_audit_events_hash", "hash"),
    )


class AuditCheckpointRow(AuditBase):
    __tablename__ = "audit_checkpoints"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    ts: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)   # periodic | manual | retention
    key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)    # hex Ed25519 signature
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    first_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    anchors: Mapped[str] = mapped_column(Text, nullable=False, default="{}")  # JSON provider -> bool

    __table_args__ = (
        Index("ix_audit_checkpoints_seq", "seq"),
        Index("ix_audit_checkpoints_kind", "kind"),
    )


EVENTS = AuditEventRow.__table__
CHECKPOINTS = AuditCheckpointRow.__table__


def make_audit_engine(url: str) -> Engine:
    """Engine for the audit database.

    SQLite: the driver is put in autocommit mode so that the service decides
    exactly when a write transaction starts (``BEGIN IMMEDIATE`` in
    ``begin_write``); plain reads never take the write lock, so verification
    and search do not block appends. WAL + synchronous=FULL make each
    committed append durable.
    """
    if not url.startswith("sqlite"):
        return create_engine(url, future=True, pool_pre_ping=True)

    path = url.split("///", 1)[-1] if "///" in url else ""
    in_memory = path in ("", ":memory:") or "mode=memory" in url
    kwargs: dict = {"connect_args": {"check_same_thread": False, "timeout": 30}}
    if in_memory:
        # One shared connection, otherwise every pooled connection would be
        # its own empty database. Intended for tests only.
        kwargs["poolclass"] = StaticPool
    else:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(url, future=True, **kwargs)

    @event.listens_for(engine, "connect")
    def _configure(dbapi_conn, _record):  # pragma: no cover - trivial
        dbapi_conn.isolation_level = None      # explicit transaction control
        cur = dbapi_conn.cursor()
        if not in_memory:
            cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=FULL")
        cur.close()

    return engine


def init_audit_db(engine: Engine) -> None:
    """Create the audit tables if they do not exist."""
    AuditBase.metadata.create_all(engine)


def begin_write(conn: Connection) -> None:
    """Start a write transaction that excludes every other chain writer.

    SQLite: ``BEGIN IMMEDIATE`` takes the database write lock up front, so a
    second writer waits instead of reading a stale head. PostgreSQL: a
    transaction-scoped advisory lock serialises writers across processes.
    Together with the ``seq`` primary key this guarantees that two writers can
    never both extend the same head (no fork)."""
    dialect = conn.dialect.name
    if dialect == "sqlite":
        conn.exec_driver_sql("BEGIN IMMEDIATE")
    elif dialect == "postgresql":
        conn.exec_driver_sql(f"SELECT pg_advisory_xact_lock({PG_ADVISORY_LOCK_KEY})")
    # other dialects: rely on the process lock + primary-key collision retry
