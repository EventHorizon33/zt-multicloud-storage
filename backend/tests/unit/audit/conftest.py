from __future__ import annotations

import sqlite3

import pytest

from app.audit import build_audit_service
from app.config import Settings
from ._fakes import FakeAnchorStore, FakeKMS, ManualClock


@pytest.fixture
def kms() -> FakeKMS:
    return FakeKMS()


@pytest.fixture
def anchors() -> FakeAnchorStore:
    return FakeAnchorStore()


@pytest.fixture
def clock() -> ManualClock:
    return ManualClock()


@pytest.fixture
def make_service(tmp_path, kms, anchors, clock):
    created = []

    def _make(*, use_anchors: bool = True, db_name: str = "audit.db", **overrides):
        values = dict(data_dir=tmp_path, audit_database_url=f"sqlite:///{tmp_path / db_name}",
                      audit_checkpoint_every=10_000, audit_retention_days=365)
        values.update(overrides)
        settings = Settings(**values)
        svc = build_audit_service(settings, kms, anchors if use_anchors else None, clock)
        created.append(svc)
        return svc

    yield _make
    for svc in created:
        svc.close()


@pytest.fixture
def service(make_service):
    return make_service()


@pytest.fixture
def attacker(tmp_path):
    """A raw second connection to the audit DB file, as an attacker with DB
    access would have. Autocommits each statement."""
    conns = []

    def _connect(db_name: str = "audit.db") -> sqlite3.Connection:
        c = sqlite3.connect(str(tmp_path / db_name), isolation_level=None)
        conns.append(c)
        return c

    yield _connect
    for c in conns:
        c.close()
