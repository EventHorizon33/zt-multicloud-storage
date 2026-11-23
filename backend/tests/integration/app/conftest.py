"""Fixtures for the integrated application: FastAPI TestClient over the real
container (real LocalKMS, crypto engine, orchestrator, audit, auth, policy,
detection) with in-memory providers wrapped in fault injection (env=test)."""
from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pyotp
import pytest
from fastapi.testclient import TestClient

from app.auth import PasswordHasher
from app.config import Settings
from app.main import create_app
from app.storage import FaultInjectingProvider
from app.storage.memory import MemoryProvider

PASSWORD = "Correct-Horse-Battery-42"
ADMIN_PASSWORD = "Admin-Horse-Battery-4242"
PROVIDERS = ("memory-a", "memory-b", "memory-c")
TEST_IP = "198.51.100.7"


class FakeClock:
    def __init__(self) -> None:
        self._now = datetime(2026, 11, 12, 9, 0, 0, tzinfo=timezone.utc)
        self._lock = threading.Lock()

    def __call__(self) -> datetime:
        with self._lock:
            return self._now

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._now += timedelta(seconds=seconds)


def chunk_keys(provider) -> list[str]:
    inner = getattr(provider, "inner", None) or getattr(provider, "_inner", None) or provider
    return [k for k in inner.list_keys("") if not k.startswith("anchors/")]


def inner_of(provider) -> MemoryProvider:
    return getattr(provider, "inner", None) or provider._inner


@dataclass
class Env:
    client: TestClient
    app: Any
    container: Any
    clock: FakeClock
    settings: Settings
    providers: dict

    # ------------------------------------------------------------ helpers
    def register(self, username: str, password: str = PASSWORD) -> dict:
        """Register and return ``{"id", "username"}``. The API answers a
        uniform 202 (F3: it does not say whether the account was created), so
        the id is looked up in the metadata DB, as an operator would."""
        r = self.client.post("/api/auth/register", json={"username": username, "password": password})
        assert r.status_code == 202 and r.json() == {"status": "accepted"}, r.text
        from sqlalchemy import func, select

        from app.models import User
        with self.db() as db:
            u = db.execute(select(User).where(func.lower(User.username) == username.lower())).scalar_one()
            return {"id": u.id, "username": u.username, "role": u.role, "clearance": u.clearance}

    def login(self, username: str, password: str = PASSWORD, totp: str | None = None) -> str:
        body = {"username": username, "password": password}
        if totp:
            body["totp_code"] = totp
        r = self.client.post("/api/auth/login", json=body)
        assert r.status_code == 200, r.text
        return r.json()["access_token"]

    def user(self, username: str) -> str:
        self.register(username)
        return self.login(username)

    @staticmethod
    def h(token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}

    def upload(self, token: str, data: bytes, filename: str = "file.bin", classification: str | None = None,
               mime: str = "application/octet-stream"):
        form = {"classification": classification} if classification else None
        return self.client.post("/api/files", headers=self.h(token), data=form,
                                files={"file": (filename, data, mime)})

    def upload_ok(self, token: str, data: bytes, **kw) -> dict:
        r = self.upload(token, data, **kw)
        assert r.status_code == 201, r.text
        return r.json()

    def download(self, token: str, file_id: str):
        return self.client.get(f"/api/files/{file_id}/download", headers=self.h(token))

    def totp(self, secret: str) -> str:
        return pyotp.TOTP(secret).at(self.clock())

    def enable_mfa(self, token: str, *, step_up: bool = True) -> str:
        """Enrol + activate a TOTP factor for the token's user. Activation does
        NOT make the session MFA-verified (ADR-0010, F1), so by default the
        helper then proves the new factor with a step-up on the same session
        (next time step), which is what the UI asks the user to do."""
        r = self.client.post("/api/auth/mfa/enroll", headers=self.h(token))
        assert r.status_code == 200, r.text
        secret = r.json()["secret"]
        r = self.client.post("/api/auth/mfa/activate", headers=self.h(token), json={"code": self.totp(secret)})
        assert r.status_code == 200, r.text
        assert r.json()["mfa_fresh"] is False
        if step_up:
            self.step_up(token, secret)
        return secret

    def step_up(self, token: str, secret: str) -> None:
        self.clock.advance(31)                     # next TOTP time step (replay guard)
        r = self.client.post("/api/auth/mfa/verify", headers=self.h(token), json={"code": self.totp(secret)})
        assert r.status_code == 200, r.text

    def admin(self) -> tuple[str, str]:
        """(token, totp secret) for the bootstrap admin, MFA-verified."""
        token = self.login("root", ADMIN_PASSWORD)
        secret = self.enable_mfa(token)
        return token, secret

    def db(self):
        return self.container.db()

    def fault(self, provider: str, mode: str, **params) -> None:
        self.providers[provider].set_mode(mode, **params)

    def audit_events(self, **filters) -> list[dict]:
        events, _ = self.container.audit.search(limit=1000, order="asc", **filters)
        return events


def build_env(tmp_path: Path, providers: dict | None = None, **overrides) -> tuple[Env, Any]:
    cfg = dict(env="test", data_dir=tmp_path / "data", storage_providers=",".join(PROVIDERS),
               enable_fault_injection=True, cookie_secure=False, chunk_size_bytes=4096,
               retry_base_delay_seconds=0.0, retry_max_delay_seconds=0.0, storage_timeout_seconds=5.0,
               bootstrap_admin_username="root", bootstrap_admin_password=ADMIN_PASSWORD,
               audit_checkpoint_every=50, cors_origins=["https://ui.example"],
               # The production default is require_mfa_for_login=True (ADR-0010). Most
               # integration/security tests exercise other controls with plain
               # password sessions, so the harness opts out explicitly; tests of the
               # default pass require_mfa_for_login=True (test_app_auth.py,
               # test_s11_s15_unc5537.py).
               require_mfa_for_login=False)
    cfg.update(overrides)
    settings = Settings(_env_file=None, **cfg)
    if providers is None:
        providers = {n: FaultInjectingProvider(MemoryProvider(n), sleep=lambda s: None)
                     for n in settings.provider_names}
    clock = FakeClock()
    app = create_app(settings, providers=providers, clock=clock, background=False,
                     password_hasher=PasswordHasher(time_cost=1, memory_cost_kib=8, parallelism=1))
    client = TestClient(app, base_url="https://testserver", client=(TEST_IP, 50000))
    env = Env(client=client, app=app, container=app.state.container, clock=clock, settings=settings,
              providers=providers)
    return env, client


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


@pytest.fixture
def env(make_env) -> Env:
    return make_env()
