"""Input handling and configuration findings of the external review:
regression tests (formerly PoCs asserting the vulnerable behaviour)."""
from __future__ import annotations

import base64
import logging
import os

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.auth import PasswordHasher
from app.config import Settings
from app.errors import KmsError
from app.kms import build_kms
from app.main import create_app
from app.storage.memory import MemoryProvider

FAST = dict(password_hasher=PasswordHasher(time_cost=1, memory_cost_kib=8, parallelism=1))


# --------------------------------------------------------------------------- #
# I1 -- malformed multipart was an unhandled 500
# --------------------------------------------------------------------------- #
def _multipart(env, body: bytes, boundary: str = "BOUNDARY"):
    c = TestClient(env.app, base_url="https://testserver", client=("198.51.100.7", 1),
                   raise_server_exceptions=False)
    tok = env.login("mallory")
    return c.post("/api/files", content=body, headers={
        "Authorization": f"Bearer {tok}", "Content-Type": f"multipart/form-data; boundary={boundary}"})


def test_fixed_malformed_multipart_is_a_client_error_without_traceback(make_env, caplog):
    """I1. An oversized part header -> 413 ``request-too-large``; a malformed
    body -> 400 ``bad-multipart``; never 500, no ERROR log with a traceback."""
    env = make_env(require_mfa_for_login=True)
    env.register("mallory")
    pad = b"A" * (64 * 1024)
    big = (b"--BOUNDARY\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.bin\"\r\n"
           b"X-Pad: " + pad + b"\r\n\r\nDATA\r\n--BOUNDARY--\r\n")
    garbage = b"--BOUNDARY\r\n\x00\x01 not a header line at all\r\n\r\n--BOUNDARY--\r\n"
    with caplog.at_level(logging.WARNING):
        r = _multipart(env, big)
        assert r.status_code == 413 and r.json()["error"] == "request-too-large", r.text
        assert r.json()["reasons"] == ["multipart-limit-exceeded"]
        r = _multipart(env, garbage)
        assert r.status_code == 400 and r.json()["error"] == "bad-multipart", r.text
    assert not [rec for rec in caplog.records if rec.levelno >= logging.ERROR]


# --------------------------------------------------------------------------- #
# M4 -- insecure default env=development
# --------------------------------------------------------------------------- #
def _clean_env(monkeypatch):
    for k in list(os.environ):
        if k.startswith("ZT_"):
            monkeypatch.delenv(k)


def test_fixed_default_env_is_production_and_refuses_to_start_without_a_root_key(tmp_path, monkeypatch):
    """M4. Unset ZT_ENV means production: no auto-generated root key next to
    the keystore (startup fails with a clear KmsError), and unknown env
    values are rejected."""
    _clean_env(monkeypatch)
    s = Settings(_env_file=None, data_dir=tmp_path / "data")
    assert s.env == "production"
    with pytest.raises(KmsError, match="no KMS root key configured"):
        build_kms(s)
    assert not (tmp_path / "data" / "kms" / "dev-root.key").exists()
    with pytest.raises(KmsError):
        create_app(s, providers={n: MemoryProvider(n) for n in s.provider_names}, background=False, **FAST)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, data_dir=tmp_path / "x", env="staging")


def test_fixed_production_hides_docs_and_sends_hsts(tmp_path, monkeypatch):
    """M4. In production (with a configured root key) /docs and
    /openapi.json are not served and HSTS is sent."""
    _clean_env(monkeypatch)
    s = Settings(_env_file=None, data_dir=tmp_path / "data",
                 kms_root_key=base64.b64encode(os.urandom(32)).decode())
    assert s.env == "production"
    app = create_app(s, providers={n: MemoryProvider(n) for n in s.provider_names}, background=False, **FAST)
    with TestClient(app, base_url="https://api.example") as c:
        assert c.get("/openapi.json").status_code == 404
        assert c.get("/docs").status_code == 404
        h = c.get("/api/health").headers
        assert h["strict-transport-security"].startswith("max-age=")
    assert not (tmp_path / "data" / "kms" / "dev-root.key").exists()


def test_fixed_development_conveniences_need_explicit_env(tmp_path, monkeypatch):
    """M4. With ZT_ENV=development set explicitly the dev root key, /docs and
    no-HSTS behaviour remain available for local work."""
    _clean_env(monkeypatch)
    monkeypatch.setenv("ZT_ENV", "development")
    s = Settings(_env_file=None, data_dir=tmp_path / "data")
    assert s.env == "development"
    kms = build_kms(s)
    assert (tmp_path / "data" / "kms" / "dev-root.key").exists()
    kms.ensure_keys()
    app = create_app(s, providers={n: MemoryProvider(n) for n in s.provider_names}, background=False, **FAST)
    with TestClient(app, base_url="https://api.example") as c:
        assert c.get("/openapi.json").status_code == 200
        assert "strict-transport-security" not in c.get("/api/health").headers


# --------------------------------------------------------------------------- #
# L5 -- /metrics trusted the loopback peer
# --------------------------------------------------------------------------- #
def test_fixed_metrics_need_a_token_even_from_loopback(make_env):
    """L5. No peer-based trust: behind a same-host proxy every client is
    127.0.0.1. /metrics needs the scrape token (ZT_METRICS_TOKEN, compared in
    constant time) or an admin access token."""
    scrape = "m" * 48
    env = make_env(metrics_token=scrape)
    tok = env.user("frank")
    env.upload_ok(tok, b"data")
    lo = TestClient(env.app, base_url="https://testserver", client=("127.0.0.1", 1))
    assert lo.get("/metrics").status_code == 401
    assert lo.get("/metrics", headers={"Authorization": "Bearer " + "m" * 47 + "n"}).status_code == 401
    assert lo.get("/metrics", headers=env.h(tok)).status_code == 403            # not an admin
    r = lo.get("/metrics", headers={"Authorization": f"Bearer {scrape}"})
    assert r.status_code == 200 and "zt_files_committed 1" in r.text and "zt_http_responses_total" in r.text
    admin, _ = env.admin()
    assert env.client.get("/metrics", headers=env.h(admin)).status_code == 200
    env2 = make_env()                                                           # no scrape token configured
    lo2 = TestClient(env2.app, base_url="https://testserver", client=("::1", 1))
    assert lo2.get("/metrics").status_code == 401
    with pytest.raises(ValidationError):
        Settings(_env_file=None, env="test", metrics_token="short")


# --------------------------------------------------------------------------- #
# L6 -- file verify/repair were unthrottled
# --------------------------------------------------------------------------- #
def test_fixed_file_verify_and_repair_are_rate_limited(make_env):
    """L6. verify and repair share a per-user budget
    (``rate_limit_verify_per_minute``, default 6): the 7th call is 429 and
    no further replica reads happen."""
    env = make_env(rate_limit_download_per_minute=2)
    tok = env.user("henry")
    f = env.upload_ok(tok, b"z" * 40_000)            # 10 chunks x 2 replicas (chunk size 4096)
    snap0 = env.container.orchestrator.metrics.snapshot()

    def gets(snap):
        return sum(ops.get("get", {}).get("attempts", 0) for ops in snap["counters"].values())

    limit = env.settings.rate_limit_verify_per_minute
    assert limit == 6
    codes = [env.client.post(f"/api/files/{f['id']}/verify", headers=env.h(tok)).status_code
             for _ in range(30)]
    assert codes[:limit] == [200] * limit and set(codes[limit:]) == {429}
    assert gets(env.container.orchestrator.metrics.snapshot()) - gets(snap0) <= limit * 10 * 2
    r = env.client.post(f"/api/files/{f['id']}/repair", headers=env.h(tok))
    assert r.status_code == 429                       # same budget
    rl = env.audit_events(event_type="security.rate-limited")
    assert rl and rl[0]["details"]["scope"] == "verify"


# --------------------------------------------------------------------------- #
# I2 -- unbounded integer parameters were unhandled 500s
# --------------------------------------------------------------------------- #
def test_fixed_out_of_range_integers_are_422(make_env):
    """I2. seq / from_seq / to_seq / offset are bounded (<= 2**63-1): values
    beyond SQLite's INTEGER are a 422, never an OverflowError 500."""
    env = make_env()
    tok = env.user("ivan")
    admin, _ = env.admin()
    c = TestClient(env.app, base_url="https://testserver", client=("198.51.100.7", 1),
                   raise_server_exceptions=False)
    big = str(10 ** 30)
    for r in (c.get(f"/api/audit/events/{big}", headers=env.h(tok)),
              c.get("/api/audit/events/0", headers=env.h(tok)),
              c.get("/api/audit/events", headers=env.h(tok), params={"offset": big}),
              c.get("/api/audit/export", headers=env.h(tok), params={"from_seq": big}),
              c.get("/api/audit/export", headers=env.h(tok), params={"to_seq": big}),
              c.get("/api/admin/files", headers=env.h(admin), params={"offset": big}),
              c.post("/api/audit/verify", headers=env.h(admin), json={"from_seq": int(big)})):
        assert r.status_code == 422, (r.request.url, r.text)
    assert c.get(f"/api/audit/events/{2**63 - 1}", headers=env.h(tok)).status_code == 404
