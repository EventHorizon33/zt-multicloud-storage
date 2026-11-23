from __future__ import annotations

import pytest

from app.auth.passwords import PasswordHasher
from app.auth.service import AuthService
from app.config import Settings
from app.db import init_db, make_engine, make_session_factory
from tests.unit._fakes_auth import FakeClock, FakeKms, RecordingAudit

# Cheap Argon2id parameters so the suite stays fast; production parameters
# are covered by test_auth_passwords.py.
FAST_HASHER = PasswordHasher(time_cost=1, memory_cost_kib=8, parallelism=1)
PASSWORD = "Tr0ub4dor&3-horse-staple"


@pytest.fixture
def settings(tmp_path):
    return Settings(env="test", data_dir=tmp_path, _env_file=None)


@pytest.fixture
def db(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'meta.db'}")
    init_db(engine)
    factory = make_session_factory(engine)
    s = factory()
    yield s
    s.close()
    engine.dispose()


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def kms():
    return FakeKms()


@pytest.fixture
def audit():
    return RecordingAudit()


@pytest.fixture
def svc(settings, kms, audit, clock):
    return AuthService(settings=settings, kms=kms, audit=audit, clock=clock, password_hasher=FAST_HASHER)
