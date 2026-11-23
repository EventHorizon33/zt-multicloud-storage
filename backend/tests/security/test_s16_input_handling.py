"""Scenario 16: hostile input — path traversal in filenames, header injection,
oversize uploads, malformed IDs, injection strings in search filters and
other parameters. Expected: rejected or neutralised, never a 500, never an
unsafe reflection, and nothing written outside the data directory."""
from __future__ import annotations

import os
import re
from urllib.parse import quote

import pytest

from app.models import File

from .conftest import inner_of, payload

pytestmark = pytest.mark.security

INJECTIONS = ["' OR '1'='1", "\" OR 1=1 --", "1; DROP TABLE files; --", "<script>alert(1)</script>",
              "${jndi:ldap://x/a}", "%00", "%", "_", "\\", "../../../../etc/passwd", "{{7*7}}", "' UNION SELECT *--"]


@pytest.mark.parametrize("name,stored", [
    ("../../etc/passwd", "passwd"),
    ("..\\..\\windows\\system32\\config\\SAM", "SAM"),
    ("/var/lib/zt/../../root/.ssh/authorized_keys", "authorized_keys"),
    ("....//....//x.txt", "x.txt"),
    ("normal‮txt.exe", "normaltxt.exe"),           # bidi override stripped
])
def test_s16_path_traversal_filenames_are_display_names_only(env, evidence, name, stored, tmp_path):
    ev = evidence("S16", f"Upload with filename {name!r}",
                  "sanitize_filename: last component, control/format chars removed; never a path or object key")
    alice = env.user("alice")
    before = {p for p in tmp_path.rglob("*")}
    r = env.upload(alice, payload(1), filename=name)
    assert r.status_code == 201, r.text
    assert r.json()["filename"] == stored
    meta = r.json()
    created = {p for p in tmp_path.rglob("*")} - before
    assert not any(p.name in (stored, "passwd", "SAM", "authorized_keys") for p in created)
    assert not os.path.exists("/etc/passwd.zt") and not any(stored in k for p in env.providers.values()
                                                            for k in inner_of(p).list_keys(""))
    d = env.download(alice, meta["id"])
    cd = d.headers["content-disposition"]
    assert "/" not in cd.split("filename*=")[0] and "\\" not in cd and ".." not in cd.split(";")[1]
    e = env.audit_events(event_type="file.upload", resource_id=meta["id"])[-1]
    assert stored not in str(e) and name not in str(e)               # names never enter the audit log
    ev.result(f"201, stored display name {stored!r}; Content-Disposition: {cd}")
    ev.audit(e)


def test_s16_unusable_filenames_rejected(env, evidence):
    ev = evidence("S16", "Upload with filename '..', '/', control-only or 300 chars",
                  "sanitize_filename -> 422 invalid-filename")
    alice = env.user("alice")
    for name in ("..", "/", "a" * 300, "./"):
        r = env.upload(alice, payload(0.2), filename=name)
        assert r.status_code == 422 and r.json()["reasons"] == ["invalid-filename"], (name, r.text)
    with env.db() as db:
        assert db.query(File).count() == 0
    ev.response(r)
    ev.audit(None)
    ev.result("rejected before the PEP: no file row, no audit record")


def test_s16_header_and_markup_injection_in_filename(env, evidence):
    ev = evidence("S16", "Filename with quotes/CRLF/;/<script> to break Content-Disposition or inject HTML",
                  "RFC 6266 ASCII fallback + percent-encoded filename*; downloads always octet-stream attachment")
    alice = env.user("alice")
    name = 'evil";\r\nSet-Cookie: zt_refresh=x; filename=<script>alert(1)</script>.html'
    r = env.upload(alice, payload(0.5), filename=name, mime="text/html")
    assert r.status_code == 201, r.text
    d = env.download(alice, r.json()["id"])
    cd = d.headers["content-disposition"]
    assert "\r" not in cd and "\n" not in cd and "set-cookie" not in {k.lower() for k in d.headers if k != "content-disposition"}
    m = re.match(r'^attachment; filename="([^"]*)"; filename\*=UTF-8\'\'(\S+)$', cd)
    assert m, cd
    assert "<" not in m.group(1) and ";" not in m.group(1)
    assert d.headers["content-type"] == "application/octet-stream"
    assert d.headers["x-content-type-options"] == "nosniff"
    listed = env.client.get("/api/files", headers=env.h(alice))
    assert listed.headers["content-type"].startswith("application/json")
    assert "default-src 'none'" in listed.headers["content-security-policy"]
    ev.result(f"Content-Disposition: {cd}")
    ev.audit(None)


def test_s16_oversize_upload_rejected_and_cleaned_up(make_env, evidence):
    ev = evidence("S16", "Upload larger than ZT_MAX_UPLOAD_BYTES (declared, and streamed past the cap)",
                  "Middleware body cap (413 before any work) + engine max_bytes (413, file FAILED, chunks deleted)")
    env = make_env(max_upload_bytes=64 * 1024)
    alice = env.user("alice")
    # 1) streamed past the service cap but under the transport cap (cap + 1 MiB)
    r = env.upload(alice, os.urandom(64 * 1024 + 5000))
    assert r.status_code == 413 and r.json()["error"] == "request-too-large", r.text
    e = env.audit_events(event_type="file.upload")[-1]
    assert (e["outcome"], e["reason"]) == ("failure", "upload-too-large")
    with env.db() as db:
        row = db.query(File).one()
        assert row.status == "failed" and row.failure_reason == "upload-too-large" and row.wrapped_dek is None
    assert all(not [k for k in inner_of(p).list_keys("") if not k.startswith("anchors/")]
               for p in env.providers.values())
    # 2) declared far beyond the transport cap -> refused by the middleware before auth/parsing
    big = env.req("POST", "/api/files", alice, content=b"x" * (64 * 1024 + 2 * 1024 * 1024),
                  headers={"Content-Type": "multipart/form-data; boundary=zzz"})
    assert big.status_code == 413
    # 3) oversize JSON body on a JSON endpoint
    j = env.req("POST", "/api/auth/login", content=b'{"username":"' + b"a" * 70000 + b'"}',
                headers={"Content-Type": "application/json"})
    assert j.status_code == 413
    ev.response(r, "streamed past cap")
    ev.audit(e)


MALFORMED_IDS = ["' OR '1'='1", "1;DROP TABLE files", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "A" * 4000,
                 "ABCDEFABCDEFABCDEFABCDEFABCDEFAB", "0" * 31, "0" * 33, "<script>alert(1)</script>",
                 "é" * 32, "null", "-1", "*"]


@pytest.mark.parametrize("bad_id", MALFORMED_IDS, ids=[f"id{i}" for i in range(len(MALFORMED_IDS))])
def test_s16_malformed_file_ids(env, evidence, bad_id):
    ev = evidence("S16", "Malformed / injection file ids on every file route",
                  "FILE_ID_RE (^[0-9a-f]{32}$) before any query; parametrised SQL; 404 for all")
    alice = env.user("alice")
    meta = env.upload_ok(alice, payload(1))
    for method, path in (("GET", "/api/files/{}"), ("GET", "/api/files/{}/download"),
                         ("DELETE", "/api/files/{}"), ("GET", "/api/files/{}/distribution"),
                         ("POST", "/api/files/{}/verify")):
        r = env.req(method, path.format(quote(bad_id, safe="")), alice)
        assert r.status_code == 404, (path, r.status_code, r.text[:200])
        body = r.json()
        body.pop("request_id")
        assert body == {"error": "not-found", "reasons": []} and "<script>" not in r.text
    evs = [x for x in env.events_for(r) if x["event_type"] == "authz.decision"]
    if evs:                                   # reached the file service: audited deny, id not stored
        e = evs[-1]
        assert e["outcome"] == "denied" and e["reason"] == "not-found" and e["resource_id"] is None
    else:                                     # an encoded '/' or '%' made the router reject it: no handler ran
        e = None
        assert "/" in bad_id or "%" in bad_id
    assert env.download(alice, meta["id"]).status_code == 200     # DB intact
    ev.response(r)
    ev.audit(e)


def test_s16_injection_strings_in_audit_search_filters(env, evidence):
    ev = evidence("S16", "SQL/LIKE/template injection strings in every audit search filter",
                  "SQLAlchemy bound parameters; LIKE autoescape; strict query validation")
    auditor = env.auditor()
    alice = env.user("alice")
    env.upload_ok(alice, payload(1))
    _, total_before = env.container.audit.search(limit=1)
    for inj in INJECTIONS:
        for param in ("event_type", "actor", "action", "resource_id", "resource_type", "request_id"):
            r = env.req("GET", f"/api/audit/events?{param}={quote(inj, safe='')}", auditor)
            assert r.status_code in (200, 422), (param, inj, r.status_code)
            if r.status_code == 200:
                assert r.json()["total"] == 0, (param, inj, r.json()["total"])
            assert "<script>" not in r.text
    for q in ("from=not-a-date", "limit=100000", "order=desc;drop", "outcome=' OR 1=1", "severity=<x>"):
        r = env.req("GET", f"/api/audit/events?{q}", auditor)
        assert r.status_code == 422 and r.json()["error"] == "validation-failed", q
        assert "<x>" not in r.text and "drop" not in r.text
    # a normal user cannot widen the scope with an injected actor filter
    r = env.req("GET", "/api/audit/events?actor=" + quote("' OR ''='", safe=""), alice)
    assert r.status_code == 200 and r.json()["scope"] == "own"
    assert {e["actor"] for e in r.json()["events"]} <= {env.me(alice)["audit_pseudonym"]}
    _, total_after = env.container.audit.search(limit=1)
    assert total_after >= total_before
    rep = env.req("POST", "/api/audit/verify", auditor, json={}).json()
    assert rep["ok"] is True
    ev.result(f"{len(INJECTIONS)} payloads x 6 filters -> 200 total=0 or 422; never 500; chain verifies")
    ev.audit(env.audit_events(event_type="audit.verify")[-1])


def test_s16_injection_in_login_register_share(env, evidence):
    ev = evidence("S16", "Injection strings as username at login/register/share target",
                  "Username pattern ^[A-Za-z0-9_.-]{3,64}$; generic 401; one share-target-invalid code")
    alice = env.user("alice")
    secret = env.enable_mfa(alice)
    meta = env.upload_ok(alice, payload(0.5))
    env.step_up(alice, secret)
    for inj in INJECTIONS:
        r = env.req("POST", "/api/auth/login", json={"username": inj[:64], "password": "x" * 12})
        assert r.status_code == 401 and r.json()["reasons"] == [] and "<script>" not in r.text
        r = env.req("POST", "/api/auth/register", json={"username": inj[:64], "password": "Valid-Passw0rd-123"})
        assert r.status_code == 422 and "<script>" not in r.text
        r = env.req("POST", f"/api/files/{meta['id']}/shares", alice, json={"username": inj[:64]})
        assert r.status_code == 422 and r.json()["reasons"] == ["share-target-invalid"], r.text
    e = env.one(r, "file.share")
    assert (e["outcome"], e["reason"]) == ("failure", "share-target-invalid")
    ev.response(r, "share to injected username")
    ev.audit(e)


def test_s16_request_id_header_cannot_inject_into_logs(env, evidence):
    ev = evidence("S16", "Hostile X-Request-ID (CRLF, JSON, 500 chars)",
                  "Request id always server-generated (L8); a client X-Request-ID is kept only if "
                  "[A-Za-z0-9._-]{1,64}, as client_request_id, otherwise dropped")
    alice = env.user("alice")
    for bad in ('x"}\r\n{"admin":true', "a" * 500, "<script>alert(1)</script>"):
        r = env.client.get("/api/files/" + "ab" * 16, headers={**env.h(alice), "X-Request-ID": bad})
        assert r.status_code == 404
        assert r.headers["x-request-id"] != bad and re.fullmatch(r"[0-9a-f]{32}", r.headers["x-request-id"])
        assert "x-client-request-id" not in r.headers
        e = env.audit_events(request_id=r.headers["x-request-id"])
        assert e and e[-1]["request_id"] == r.headers["x-request-id"]
        assert "client_request_id" not in e[-1]["details"]
    ev.result("hostile ids dropped; server-generated id in response, logs and audit; no client_request_id kept")
    ev.audit(e[-1])
