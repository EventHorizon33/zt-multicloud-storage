"""External security review: regression tests. Reuses the integration
harness (real container behind a FastAPI TestClient, injected clock,
in-memory providers). Every test here started as an auditor's PoC that
asserted the VULNERABLE behaviour; after the fixes each asserts the FIXED
behaviour (``test_fixed_*``). See docs/SECURITY_TESTING.md, "Independent
review"."""
from __future__ import annotations

import pytest

from tests.integration.app.conftest import (  # noqa: F401
    ADMIN_PASSWORD, PASSWORD, TEST_IP, Env, build_env, inner_of,
)


@pytest.fixture
def make_env(tmp_path):
    opened = []

    def factory(**overrides) -> Env:
        sub = tmp_path / f"env{len(opened)}"
        env, client = build_env(sub, **overrides)
        client.__enter__()
        opened.append(client)
        return env

    yield factory
    for c in opened:
        c.__exit__(None, None, None)


def set_cidrs(env: Env, user_id: str, cidrs: list[str]) -> None:
    from app.models import User
    with env.db() as db:
        u = db.get(User, user_id)
        u.allowed_cidrs = cidrs
        db.commit()


def set_role(env: Env, user_id: str, role: str) -> None:
    from app.models import User
    with env.db() as db:
        u = db.get(User, user_id)
        u.role = role
        db.commit()
