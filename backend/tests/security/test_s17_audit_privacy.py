"""Scenario 17: audit privacy. After every other scenario has run, scan the RAW
audit databases (main file + WAL + SHM bytes, i.e. what a thief of the audit
DB would get) for every password, token, refresh token, TOTP seed and code,
filename, username-as-password slip and file-content marker those scenarios
used, plus full client IP addresses (only generalised /24 networks may be
stored).

Runs last (file name order). Run on its own it still exercises its own
dedicated flow, so the scan is never vacuous."""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from .conftest import ADMIN_PASSWORD, MARKER, PASSWORD, REGISTRY, payload, remember

pytestmark = pytest.mark.security

FULL_IPS = ["198.51.100.7", "192.0.2.66", "192.0.2.99", "203.0.113.50", "203.0.113.77", "10.20.3.4"]


def _raw(db: Path) -> bytes:
    return b"".join(p.read_bytes() for p in sorted(db.parent.glob(db.name + "*")) if p.is_file())


def _decoded_fields(db: Path) -> list[str]:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = conn.execute("SELECT reason, details, resource_id, request_id FROM audit_events").fetchall()
    finally:
        conn.close()
    return [" ".join(str(x) for x in r if x is not None) for r in rows]


def _dedicated_flow(make_env) -> None:
    """A flow that touches every credential type with distinctive values."""
    env = make_env(detect_max_downloads_in_window=4)
    pw_a, pw_b, wrong = "Privacy-Pass-Alpha-9137", "Privacy-Pass-Bravo-5521", "Privacy-Wrong-Guess-0042"
    user_a, user_b = "privacy-user-alpha-x7", "privacy-user-bravo-y8"
    remember(pw_a, pw_b, wrong, user_a, user_b)
    env.register(user_a, pw_a)
    env.register(user_b, pw_b)
    # password typed into the username field (a classic slip) and a wrong password
    env.client.post("/api/auth/login", json={"username": pw_a, "password": pw_a})
    env.client.post("/api/auth/login", json={"username": user_a, "password": wrong})
    tok = env.login(user_a, pw_a)
    secret = env.enable_mfa(tok)
    fname = "privacy-tax-return-2026-secret.pdf"
    meta = env.upload_ok(tok, payload(2), filename=fname, classification="confidential")
    env.step_up(tok, secret)
    for _ in range(5):
        env.download(tok, meta["id"])                       # bulk-download detector fires
    env.client.post(f"/api/files/{meta['id']}/shares", headers=env.h(tok), json={"username": user_b})
    env.clock.advance(31)
    wrong_code = "000000" if env.totp(secret) != "000000" else "999999"
    remember(wrong_code)
    env.client.post("/api/auth/mfa/verify", headers=env.h(tok), json={"code": wrong_code})
    env.client.post("/api/auth/password", headers=env.h(tok),
                    json={"current_password": pw_a, "new_password": "Privacy-Pass-Charlie-7788"})
    remember("Privacy-Pass-Charlie-7788")
    stolen = env.client.cookies.get("zt_refresh")
    env.client.post("/api/auth/refresh")
    TestClient(env.app, base_url="https://testserver", client=("192.0.2.99", 1),
               cookies={"zt_refresh": stolen}).post("/api/auth/refresh")
    # admin side: pseudonym lookup, policy change, audit verify
    admin, _ = env.admin()
    pseudo = env.me(env.login(user_b, pw_b))["audit_pseudonym"]
    env.client.post("/api/admin/pseudonym-lookup", headers=env.h(admin), json={"pseudonym": pseudo})
    env.client.post("/api/audit/verify", headers=env.h(admin), json={})


def test_s17_no_secret_in_any_audit_database(make_env, evidence):
    ev = evidence("S17", "Steal the audit DB files after all scenarios; grep for every secret used",
                  "Privacy filter: allow-listed detail keys, deny-name/value scan, pseudonymous actors, /24 IPs")
    _dedicated_flow(make_env)
    remember(PASSWORD, ADMIN_PASSWORD, MARKER)
    dbs = [p for p in dict.fromkeys(REGISTRY.audit_dbs) if p.exists()]
    assert dbs, "no audit databases registered"
    long_secrets = sorted(REGISTRY.secrets)
    assert len(long_secrets) >= 20
    hits = []
    events = 0
    controls = {"raw": 0, "decoded": 0}
    for db in dbs:
        raw = _raw(db)
        controls["raw"] += b"198.51.100.0/24" in raw            # positive control: stored data IS readable
        controls["decoded"] += any("not-owner" in f or "mfa" in f for f in _decoded_fields(db))
        for s in long_secrets:
            if s.encode("utf-8", "replace") in raw:
                hits.append((db.parent.name, "secret", s[:12] + "..."))
        for ip in FULL_IPS:
            if ip.encode() in raw:
                hits.append((db.parent.name, "full-ip", ip))
        fields = _decoded_fields(db)
        events += len(fields)
        blob = "\n".join(fields)
        for code in REGISTRY.short_codes:
            if re.search(rf"(?<![\d.]){code}(?!\d)", blob):
                hits.append((db.parent.name, "totp-code", code))
    assert controls["raw"] > 0 and controls["decoded"] > 0, controls
    assert hits == [], hits[:20]
    ev.result(f"{len(dbs)} audit DBs, {events} events, {len(long_secrets)} long secrets + "
              f"{len(REGISTRY.short_codes)} TOTP codes + {len(FULL_IPS)} full IPs: 0 hits")
    ev.audit(None)


def test_s17_no_detail_key_was_dropped_and_actor_is_pseudonymous(make_env, evidence):
    """The privacy filter must not silently drop fields an investigator needs
    (``_dropped``), and the actor column must always be a pseudonym."""
    ev = evidence("S17", "Check every stored event: actor format, no _dropped detail keys",
                  "Pseudonym = 'u_' + HMAC(user id)[:32]; allow-list covers every emitter")
    _dedicated_flow(make_env)
    bad = []
    for db in [p for p in dict.fromkeys(REGISTRY.audit_dbs) if p.exists()]:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        for actor, details, et in conn.execute("SELECT actor, details, event_type FROM audit_events"):
            if actor is not None and not re.fullmatch(r"u_[0-9a-f]{32}", actor):
                bad.append(("actor", et, actor))
            if details and "_dropped" in json.loads(details):
                bad.append(("dropped", et, details[:120]))
        conn.close()
    assert bad == [], bad[:10]
    ev.result("every actor matches u_<32 hex>; no _dropped markers")
    ev.audit(None)
