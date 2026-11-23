from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from app.config import Settings
from app.contracts import Classification, RequestContext, Resource, Role, Subject
from app.db import init_db, make_engine, make_session_factory
from tests.unit._fakes_auth import FakeClock, RecordingAudit

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)
ME, OTHER = "user-me", "user-other"


def subject(role: Role = Role.USER, **over) -> Subject:
    base = Subject(user_id=ME, role=role, clearance=Classification.RESTRICTED, session_id="sess-1",
                   mfa_enrolled=True, mfa_verified=True, mfa_age_seconds=10.0, session_age_seconds=60.0,
                   allowed_cidrs=(), is_active=True)
    return replace(base, **over)


def file_res(owner: str = ME, **over) -> Resource:
    base = Resource(type="file", id="file-1", owner_id=owner, classification=Classification.INTERNAL,
                    shared_with_subject=False, status="committed")
    return replace(base, **over)


def ctx(**over) -> RequestContext:
    return replace(RequestContext(request_id="req-1", source_ip="203.0.113.5", now=NOW), **over)


@pytest.fixture
def audit():
    return RecordingAudit()


@pytest.fixture
def settings(tmp_path):
    # require_mfa_for_login defaults to True since ADR-0010; these PEP/store
    # tests switch it on themselves where they test it.
    return Settings(env="test", data_dir=tmp_path, _env_file=None, require_mfa_for_login=False)


@pytest.fixture
def db(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'meta.db'}")
    init_db(engine)
    s = make_session_factory(engine)()
    yield s
    s.close()
    engine.dispose()


@pytest.fixture
def clock():
    return FakeClock(NOW)
