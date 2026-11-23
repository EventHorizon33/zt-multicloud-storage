"""Scenarios 1 and 2: unauthenticated and expired-token access to files.

Mechanism under test: ``app/api/deps.get_caller`` -> ``AuthService.authenticate_request``
(pinned EdDSA, signature through the KMS, iss/aud/typ/exp checks, DB re-read of
session + user on every request). 401 bodies never echo the internal reason;
the reason is in the audit record (``auth.token``)."""
from __future__ import annotations

import base64
import json
import pytest
from fastapi.testclient import TestClient

from app.auth.tokens import TokenService
from app.config import Settings

from .conftest import MARKER, payload

pytestmark = pytest.mark.security


def _b64(obj) -> str:
    raw = obj if isinstance(obj, bytes) else json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _assert_401(r):
    assert r.status_code == 401, r.text
    body = r.json()
    assert body["error"] == "unauthenticated" and body["reasons"] == []     # reason never echoed
    assert r.headers["www-authenticate"] == "Bearer"
    assert MARKER not in r.content


FILE_ROUTES = [("GET", "/api/files/{id}/download"), ("GET", "/api/files/{id}"), ("DELETE", "/api/files/{id}"),
               ("GET", "/api/files/{id}/distribution"), ("POST", "/api/files/{id}/shares")]


def test_s01_no_token_is_401_and_counted(env, evidence):
    ev = evidence("S01", "Request alice's file with no Authorization header",
                  "get_caller: bearer token required on every file route")
    alice = env.user("alice")
    meta = env.upload_ok(alice, payload())
    request_ids = []
    for method, path in FILE_ROUTES:
        r = env.req(method, path.format(id=meta["id"]), json={"username": "x"} if method == "POST" else None)
        _assert_401(r)
        request_ids.append(r.request_id)
    ev.response(r, "no token")
    # Design: an anonymous request without any credential is not an audit event (no identity, no
    # token to analyse); it is counted in the Prometheus response counter instead.
    for x in request_ids:
        assert env.events_for(x) == []
    admin, _ = env.admin()                      # /metrics needs an admin or the scrape token (L5)
    metrics = env.client.get("/metrics", headers=env.h(admin)).text
    line = next(l for l in metrics.splitlines() if l.startswith('zt_http_responses_total{status="401"}'))
    assert int(float(line.split()[-1])) >= len(FILE_ROUTES)
    ev.audit(None)
    ev.result("not audited by design; zt_http_responses_total{status=401} incremented")


def test_s01_garbage_token_is_401_and_audited(env, evidence):
    ev = evidence("S01", "Present a garbage bearer token", "TokenService.verify_access_token (format check)")
    alice = env.user("alice")
    meta = env.upload_ok(alice, payload())
    r = env.req("GET", f"/api/files/{meta['id']}/download", "not.a.jwt")
    _assert_401(r)
    e = env.one(r, "auth.token")
    assert (e["outcome"], e["severity"], e["reason"], e["actor"]) == ("failure", "warning", "token-malformed", None)
    ev.response(r)
    ev.audit(e)


@pytest.mark.parametrize("header,reason", [
    ({"alg": "none", "typ": "JWT"}, "token-alg-not-allowed"),
    ({"alg": "HS256", "typ": "JWT"}, "token-alg-not-allowed"),
])
def test_s01_algorithm_confusion_is_refused(env, evidence, header, reason):
    ev = evidence("S01", f"Forge a token with alg={header['alg']} (algorithm confusion)",
                  "Algorithm pinned to EdDSA before any signature work")
    token = env.user("alice")
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    claims["sub"] = env.user_id(token)
    forged = f"{_b64(header)}.{_b64(claims)}." + ("" if header["alg"] == "none" else _b64(b"x" * 32))
    r = env.req("GET", "/api/files", forged)
    _assert_401(r)
    e = env.one(r, "auth.token")
    assert (e["outcome"], e["reason"]) == ("failure", reason)
    ev.response(r)
    ev.audit(e)


def test_s01_token_from_another_deployment_key_is_refused(env, make_env, evidence):
    ev = evidence("S01", "Replay a validly signed token minted by ANOTHER deployment (different KMS key)",
                  "Ed25519 signature verified with this deployment's KMS token-signing key")
    victim_token = env.user("alice")
    meta = env.upload_ok(victim_token, payload())
    other = make_env()                                   # independent keystore => different signing key
    foreign = other.user("alice")                        # same username, valid token over there
    r = env.req("GET", f"/api/files/{meta['id']}/download", foreign)
    _assert_401(r)
    e = env.one(r, "auth.token")
    assert (e["outcome"], e["severity"], e["reason"]) == ("failure", "warning", "token-bad-signature")
    ev.response(r)
    ev.audit(e)


@pytest.mark.parametrize("field,value,reason", [
    ("token_issuer", "some-other-service", "token-wrong-issuer"),
    ("token_audience", "some-other-api", "token-wrong-audience"),
])
def test_s01_token_for_another_issuer_or_audience_is_refused(env, evidence, field, value, reason):
    """Even a token signed with THIS deployment's key (e.g. a sibling service sharing the KMS)
    is refused if it was issued for another issuer/audience."""
    ev = evidence("S01", f"Token signed by the same key but {field.split('_')[1]}={value}",
                  f"iss/aud claim validation ({reason})")
    token = env.user("alice")
    me = env.me(token)
    other_settings = Settings(_env_file=None, **{**env.settings.model_dump(), field: value})
    minted, _ = TokenService(env.container.kms, other_settings, env.clock).issue_access_token(
        user_id=me["user"]["id"], session_id=me["session"]["id"])
    r = env.req("GET", "/api/files", minted)
    _assert_401(r)
    e = env.one(r, "auth.token")
    assert e["reason"] == reason
    ev.response(r)
    ev.audit(e)


def test_s01_modified_payload_breaks_signature(env, evidence):
    ev = evidence("S01", "Take a valid token and change sub to another user's id",
                  "Ed25519 signature over header+payload")
    alice = env.user("alice")
    bob = env.user("bob")
    meta = env.upload_ok(alice, payload())
    h, p, s = bob.split(".")
    claims = json.loads(base64.urlsafe_b64decode(p + "=="))
    claims["sub"] = env.user_id(alice)
    r = env.req("GET", f"/api/files/{meta['id']}/download", f"{h}.{_b64(claims)}.{s}")
    _assert_401(r)
    e = env.one(r, "auth.token")
    assert e["reason"] == "token-bad-signature"
    ev.response(r)
    ev.audit(e)


def test_s02_expired_token_is_refused(env, evidence):
    ev = evidence("S02", "Replay an access token after its 300 s lifetime",
                  "Strict exp check (no leeway); session row re-read")
    alice = env.user("alice")
    meta = env.upload_ok(alice, payload())
    assert env.download(alice, meta["id"]).status_code == 200
    env.clock.advance(env.settings.access_token_ttl_seconds + 1)
    r = env.req("GET", f"/api/files/{meta['id']}/download", alice)
    _assert_401(r)
    # Design (app/auth/NOTES.md): ordinary expiry is not a security event, so no auth.token record.
    assert env.events_for(r) == []
    # ...but the expiry is enforced exactly at exp: one second earlier the same token works.
    fresh = env.login("alice")
    env.clock.advance(env.settings.access_token_ttl_seconds - 1)
    assert env.download(fresh, meta["id"]).status_code == 200
    env.clock.advance(1)
    _assert_401(env.req("GET", f"/api/files/{meta['id']}/download", fresh))
    ev.response(r)
    ev.audit(None)
    ev.result("expiry is enforced at exactly exp; not audited by design (routine)")


def test_s02_expired_session_is_refused_and_audited(env, evidence):
    """Idle expiry of the SESSION (not the token) is a security-relevant event and is audited."""
    ev = evidence("S02", "Use a still-valid token whose session has been idle > 30 min",
                  "Session idle expiry checked on every request; session revoked")
    alice = env.user("alice")
    me = env.me(alice)
    env.clock.advance(env.settings.session_idle_ttl_seconds + 1)
    # mint a token that is itself valid "now" for the idle session (e.g. obtained just before)
    token, _ = env.container.auth.tokens.issue_access_token(user_id=me["user"]["id"],
                                                            session_id=me["session"]["id"])
    r = env.req("GET", "/api/files", token)
    _assert_401(r)
    e = env.one(r, "auth.session")
    assert (e["outcome"], e["reason"]) == ("failure", "session-idle-expired")
    ev.response(r)
    ev.audit(e)


def test_s02_refresh_after_absolute_session_expiry_is_refused(env, evidence):
    ev = evidence("S02", "Use the refresh cookie after the 12 h absolute session lifetime",
                  "Absolute session expiry; refresh bounded by session expiry")
    env.user("alice")
    for _ in range(int(env.settings.session_absolute_ttl_seconds // (25 * 60)) + 1):
        env.clock.advance(25 * 60)                      # stay under the idle limit
        r = env.req("POST", "/api/auth/refresh")
        if r.status_code != 200:
            break
    assert r.status_code == 401
    e = env.one(r, "auth.refresh")
    assert e["outcome"] == "failure" and e["reason"] in ("refresh-expired", "session-expired")
    ev.response(r)
    ev.audit(e)
