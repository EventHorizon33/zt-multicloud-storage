"""Phase 8 security-validation fixtures.

Reuses the integration harness (``tests/integration/app/conftest.py``): the
REAL container (LocalKMS, crypto engine, orchestrator, audit, auth, policy,
detection) behind a FastAPI ``TestClient``, an injected clock, and in-memory
providers wrapped in fault injection. The emulator scenarios
(``test_e01_provider_failures.py``) swap in the real S3/Azure/GCS adapters.

Three things are added for the attack scenarios:

* ``SecEnv`` — helpers to correlate an attack request with its audit records
  (every attack request carries its own ``X-Request-ID``), to promote an
  auditor, and to open the audit DB the way an attacker with DB access would
  (raw ``sqlite3``).
* A session-wide SECRET REGISTRY. Every password, access token, refresh token,
  TOTP seed and code, filename and file-content marker that a scenario uses
  is remembered together with that scenario's audit DB path. Scenario 17
  (``test_s17_audit_privacy.py``) scans every registered audit DB for every
  registered secret after all other scenarios have run.
* An EVIDENCE recorder: each scenario writes what it attempted, the mechanism
  that stopped it, the observed response and the observed audit record. With
  ``ZT_SECURITY_EVIDENCE=<path>`` the collected rows (plus the pytest outcome
  of each test) are written as JSON at the end of the session; that file is
  what ``scripts/attacks/run_all.sh`` turns into the results table.
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from tests.integration.app.conftest import ADMIN_PASSWORD, PASSWORD, Env, build_env, inner_of  # noqa: F401

MARKER = b"ZT-PLAINTEXT-MARKER-7f3a"      # appears in every uploaded test file


# --------------------------------------------------------------------------- #
# secret registry (scenario 17)
# --------------------------------------------------------------------------- #
@dataclass
class _Registry:
    secrets: set[str] = field(default_factory=set)        # long secrets: scanned as raw bytes
    short_codes: set[str] = field(default_factory=set)     # 6-digit TOTP codes: scanned in decoded fields
    audit_dbs: list[Path] = field(default_factory=list)
    scenarios: list[str] = field(default_factory=list)


REGISTRY = _Registry()


def remember(*values: Any) -> None:
    for v in values:
        if v is None:
            continue
        if isinstance(v, bytes):
            v = v.decode("latin-1")
        v = str(v)
        if v.isdigit() and len(v) <= 8:
            REGISTRY.short_codes.add(v)
        elif len(v) >= 6:
            REGISTRY.secrets.add(v)


# --------------------------------------------------------------------------- #
# evidence (scripts/attacks/run_all.sh, docs/SECURITY_TESTING.md)
# --------------------------------------------------------------------------- #
_EVIDENCE: dict[str, dict] = {}
_OUTCOMES: dict[str, str] = {}
_XFAIL_REASONS: dict[str, str] = {}


def summarize_event(e: dict | None) -> str:
    if not e:
        return "(none)"
    parts = [e["event_type"], e["outcome"], e["severity"]]
    if e.get("reason"):
        parts.append(f"reason={e['reason']}")
    det = e.get("details") or {}
    for k in ("reasons", "finding_types", "provider", "count", "distinct_accounts", "failed_count"):
        if k in det:
            parts.append(f"{k}={det[k]}")
    return " ".join(str(p) for p in parts)


class Evidence:
    def __init__(self, nodeid: str) -> None:
        self.nodeid = nodeid
        self.row = {"scenario": "", "attempt": "", "mechanism": "", "result": [], "audit": []}

    def __call__(self, scenario: str, attempt: str, mechanism: str) -> "Evidence":
        self.row.update(scenario=scenario, attempt=attempt, mechanism=mechanism)
        _EVIDENCE[self.nodeid] = self.row
        return self

    def result(self, text: str) -> None:
        self.row["result"].append(text)

    def response(self, r, label: str = "") -> None:
        try:
            body = r.json()
            text = f"{r.status_code} {body.get('error', '')} {body.get('reasons', '')}".strip()
        except Exception:
            text = f"{r.status_code} ({len(r.content)} bytes)"
        self.result((label + ": " if label else "") + text)

    def audit(self, event: dict | None) -> None:
        self.row["audit"].append(summarize_event(event))


@pytest.fixture
def evidence(request) -> Evidence:
    return Evidence(request.node.nodeid)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if rep.when == "call" or (rep.when == "setup" and rep.outcome != "passed"):
        state = rep.outcome
        if hasattr(rep, "wasxfail"):
            state = "xfailed" if rep.skipped else "xpassed"
            _XFAIL_REASONS[item.nodeid] = str(rep.wasxfail).removeprefix("reason: ")
        _OUTCOMES[item.nodeid] = state


def pytest_sessionfinish(session, exitstatus):
    path = os.environ.get("ZT_SECURITY_EVIDENCE")
    if not path:
        return
    rows = []
    for nodeid, outcome in _OUTCOMES.items():
        if "tests/security/" not in nodeid.replace("\\", "/"):
            continue
        row = dict(_EVIDENCE.get(nodeid, {}))
        row.setdefault("scenario", "")
        row["test"] = nodeid
        row["outcome"] = outcome
        if nodeid in _XFAIL_REASONS:
            row["xfail_reason"] = _XFAIL_REASONS[nodeid]
        rows.append(row)
    Path(path).write_text(json.dumps(rows, indent=1))


# --------------------------------------------------------------------------- #
# environment
# --------------------------------------------------------------------------- #
def rid() -> str:
    """A fresh request id so a single attack request can be found in the audit log."""
    return "atk-" + secrets.token_hex(8)


@dataclass
class SecEnv(Env):
    def __post_init__(self) -> None:
        REGISTRY.audit_dbs.append(self.audit_db_path)

    # ---------------------------------------------------------- secrets
    def register(self, username: str, password: str = PASSWORD) -> dict:
        remember(password)
        return super().register(username, password)

    def login(self, username: str, password: str = PASSWORD, totp: str | None = None) -> str:
        remember(password, totp)
        token = super().login(username, password, totp)
        remember(token, token.split(".")[2], self.client.cookies.get("zt_refresh"))
        return token

    def enable_mfa(self, token: str) -> str:
        secret = super().enable_mfa(token)
        remember(secret, self.totp(secret))
        return secret

    def step_up(self, token: str, secret: str) -> None:
        super().step_up(token, secret)
        remember(self.totp(secret))

    def upload(self, token: str, data: bytes, filename: str = "file.bin", classification: str | None = None,
               mime: str = "application/octet-stream"):
        remember(filename, MARKER)
        return super().upload(token, data, filename=filename, classification=classification, mime=mime)

    def admin(self) -> tuple[str, str]:
        """(token, totp secret) for the bootstrap admin, freshly MFA-verified.
        Works repeatedly (enrols MFA on first use, logs in with TOTP afterwards)."""
        cached = getattr(self, "_admin_secret", None)
        if cached is None:
            token = self.login("root", ADMIN_PASSWORD)
            self._admin_secret = self.enable_mfa(token)
            return token, self._admin_secret
        self.clock.advance(31)
        return self.login("root", ADMIN_PASSWORD, totp=self.totp(cached)), cached

    # ---------------------------------------------------------- requests
    def req(self, method: str, path: str, token: str | None = None, *, request_id: str | None = None,
            client=None, **kw):
        headers = dict(kw.pop("headers", {}) or {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        headers["X-Request-ID"] = request_id or rid()
        r = (client or self.client).request(method, path, headers=headers, **kw)
        # Since finding L8 the audit request id is always server-generated; the
        # client's value is only echoed (X-Client-Request-ID) and kept in
        # details.client_request_id. Join on the server's id.
        assert r.headers.get("x-client-request-id") == headers["X-Request-ID"]
        r.request_id = r.headers["x-request-id"]
        r.client_request_id = headers["X-Request-ID"]
        return r

    # ---------------------------------------------------------- audit
    def events_for(self, r_or_rid) -> list[dict]:
        request_id = r_or_rid if isinstance(r_or_rid, str) else r_or_rid.request_id
        return self.audit_events(request_id=request_id)

    def one(self, r_or_rid, event_type: str) -> dict:
        evs = [e for e in self.events_for(r_or_rid) if e["event_type"] == event_type]
        assert evs, f"no {event_type} audit event for the request; got " \
                    f"{[e['event_type'] for e in self.events_for(r_or_rid)]}"
        return evs[-1]

    def all_events(self) -> list[dict]:
        out, offset = [], 0
        while True:
            evs, total = self.container.audit.search(limit=1000, offset=offset, order="asc")
            out += evs
            offset += len(evs)
            if offset >= total or not evs:
                return out

    @property
    def audit_db_path(self) -> Path:
        return Path(self.settings.audit_database_url.split("///", 1)[1])

    def audit_sql(self) -> sqlite3.Connection:
        """The attacker's view: a raw connection to the audit database."""
        conn = sqlite3.connect(self.audit_db_path, isolation_level=None, timeout=10)
        return conn

    # ---------------------------------------------------------- users
    def me(self, token: str) -> dict:
        return self.client.get("/api/auth/me", headers=self.h(token)).json()

    def user_id(self, token: str) -> str:
        return self.me(token)["user"]["id"]

    def auditor(self, username: str = "audrey") -> str:
        """Register ``username`` and have the (MFA-verified) admin promote it."""
        user = self.register(username)
        admin, _ = self.admin()
        r = self.client.put(f"/api/admin/users/{user['id']}/role", headers=self.h(admin), json={"role": "auditor"})
        assert r.status_code == 200, r.text
        return self.login(username)

    def chunk_rows(self, file_id: str) -> list[tuple[str, int, list[str]]]:
        from sqlalchemy import select

        from app.models import Chunk
        with self.db() as db:
            return [(c.id, c.index, sorted(r.provider for r in c.replicas if r.status == "stored"))
                    for c in db.execute(select(Chunk).where(Chunk.file_id == file_id)
                                        .order_by(Chunk.index)).scalars()]


def make_sec_env(tmp_path: Path, opened: list, **overrides) -> SecEnv:
    cfg = dict(rate_limit_login_per_minute=10_000, rate_limit_register_per_minute=10_000)
    cfg.update(overrides)
    sub = tmp_path / f"env{len(opened)}"
    env, client = build_env(sub, **cfg)
    client.__enter__()
    opened.append(client)
    return SecEnv(**{k: getattr(env, k) for k in Env.__dataclass_fields__})


@pytest.fixture
def make_env(tmp_path, request):
    opened: list = []
    REGISTRY.scenarios.append(request.node.nodeid)

    def factory(**overrides) -> SecEnv:
        return make_sec_env(tmp_path, opened, **overrides)

    yield factory
    for c in opened:
        c.__exit__(None, None, None)


@pytest.fixture
def env(make_env) -> SecEnv:
    return make_env()


def payload(n_chunks: float = 3.5, chunk: int = 4096) -> bytes:
    """Test file content: random bytes with the plaintext marker embedded."""
    body = os.urandom(int(n_chunks * chunk))
    return MARKER + body + MARKER
