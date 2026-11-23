"""Privacy filter: secrets never reach the audit DB."""
from __future__ import annotations

import base64
import json
import os
import sqlite3

import pytest

from app.audit import privacy
from app.audit.privacy import (
    GLOBAL_ALLOWED_DETAIL_KEYS, REDACTED, filter_details, generalise_ip, is_sensitive_key,
    looks_sensitive,
)

PASSWORD = "Tr0ub4dor&3-correct-horse"
JWT = ("eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9."
       "eyJzdWIiOiJ1c2VyLTEyMyIsImV4cCI6MTcwMDAwMDAwMH0."
       "c2lnbmF0dXJlc2lnbmF0dXJlc2lnbmF0dXJlc2ln")
# Fake PEM-shaped test input (body is base64 of the words "generated key material"), not a real key.
PEM = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIGdlbmVyYXRlZGtleW1hdGVyaWFs\n-----END PRIVATE KEY-----"
HEX_KEY = os.urandom(32).hex()
B64_KEY = base64.b64encode(os.urandom(48)).decode()
EMAIL = "alice.victim@example.org"
FILENAME = "Q3-merger-plan-secret.xlsx"
USERNAME = "alice_the_admin"
TOTP = "492039"
RAW_USER_ID = "8f14e45f-ceea-467f-a0e6-raw-user-id"

SECRETS = [PASSWORD, JWT, "MC4CAQAwBQYDK2VwBCIEIGdlbmVyYXRlZGtleW1hdGVyaWFs", HEX_KEY,
           B64_KEY, EMAIL, FILENAME, USERNAME, RAW_USER_ID, "203.0.113.77", "2001:db8:abcd:12::99"]


def _all_text(db_path) -> str:
    """Every column of every row of every table, as text."""
    db = sqlite3.connect(str(db_path))
    out = []
    for (table,) in db.execute("SELECT name FROM sqlite_master WHERE type='table'"):
        for row in db.execute(f'SELECT * FROM "{table}"'):
            out.extend("" if v is None else str(v) for v in row)
    db.close()
    return "\n".join(out)


def test_secrets_never_reach_the_database(service, tmp_path):
    hostile = {
        "password": PASSWORD, "new_password": PASSWORD, "Authorization": f"Bearer {JWT}",
        "token": JWT, "refresh_token": "abc", "cookie": "sid=1", "dek": HEX_KEY,
        "private_key": PEM, "api_key": B64_KEY, "totp_code": TOTP, "seed": "JBSWY3DPEHPK3PXP",
        "filename": FILENAME, "file_name": FILENAME, "username": USERNAME, "email": EMAIL,
        "content": "plaintext bytes", "plaintext": "x",
        # allow-listed keys carrying secret-looking VALUES
        "reason": f"login with {PASSWORD} password={PASSWORD}",
        "method": f"Bearer {JWT}", "state": PEM, "mode": HEX_KEY, "kind": B64_KEY,
        "error_class": EMAIL, "reasons": ["mfa-required", JWT, EMAIL],
        "old": {"note": f"Basic {B64_KEY}", "password": PASSWORD, "threshold": 5},
        "new": {"user": EMAIL},
        # unknown keys carrying identifying data
        "name": FILENAME, "user": USERNAME, "path": "/home/alice/" + FILENAME,
    }
    service.record(event_type="auth.login", action="auth:login", outcome="failure",
                   actor_id=RAW_USER_ID, reason=f"bad password {PASSWORD} for {EMAIL}",
                   details=hostile, request_id="r1", source_ip="203.0.113.77")
    service.record(event_type="file.upload", action="file:create", outcome="success",
                   actor_id=RAW_USER_ID, resource_id=f"Bearer {JWT}", details={"size_bytes": 5},
                   source_ip="2001:db8:abcd:12::99")
    text = _all_text(tmp_path / "audit.db")
    for secret in SECRETS:
        assert secret not in text, f"leaked: {secret[:12]}..."
    assert USERNAME not in text and "JBSWY3DPEHPK3PXP" not in text
    # also no prefix of the long values (no truncated leak)
    assert PASSWORD[:10] not in text and HEX_KEY[:20] not in text and JWT[:30] not in text

    ev = service.get_event(1)
    d = ev["details"]
    assert ev["reason"] == REDACTED
    assert d["reason"] == REDACTED and d["method"] == REDACTED and d["state"] == REDACTED
    assert d["mode"] == REDACTED and d["kind"] == REDACTED and d["error_class"] == REDACTED
    assert d["reasons"] == ["mfa-required", REDACTED, REDACTED]
    assert d["old"] == {"note": REDACTED, "threshold": 5}          # nested sensitive key dropped
    assert d["new"] == {"user": REDACTED}
    # dropped top-level keys are counted but not named
    assert d["_dropped"] >= 20
    for name in ("password", "token", "filename", "username", "email", "path"):
        assert name not in d
    assert service.get_event(2)["resource_id"] == REDACTED


def test_unknown_keys_dropped_and_counted_without_names():
    out = filter_details({"size_bytes": 10, "foo": 1, "bar_baz": "x", "chunk_index": 2},
                         "chunk.distribute")
    assert out == {"size_bytes": 10, "chunk_index": 2, "_dropped": 2}
    assert filter_details(None) == {} and filter_details({}) == {}


def test_value_types_restricted_and_strings_truncated():
    out = filter_details({
        "count": 3, "ok": True, "latency_ms": 1.5, "state": None,
        "bytes": b"raw", "old": object(), "new": {"a": [1, 2]}, "providers": ["a", {"x": 1}, 2],
        "role": "r" * 1000, "threshold": float("nan"),
    })
    assert out["count"] == 3 and out["ok"] is True and out["latency_ms"] == 1.5
    assert out["state"] is None
    assert "bytes" not in out and "old" not in out and "threshold" not in out
    assert out["new"] == {}                       # nested list in dict dropped (shallow only)
    assert out["providers"] == ["a", 2]
    assert len(out["role"]) == privacy.MAX_STRING_LENGTH
    assert out["_dropped"] == 5


def test_per_event_type_allow_list():
    d = {"events_checked": 5, "size_bytes": 1}
    assert filter_details(d, "audit.verify") == d
    assert filter_details(d, "file.upload") == {"size_bytes": 1, "_dropped": 1}
    extra = {"file.*": {"events_checked"}}
    assert filter_details(d, "file.upload", extra_allowed=extra) == d


def test_hostile_mapping_never_raises():
    class Evil:
        def __iter__(self):
            raise RuntimeError("boom")
    out = filter_details({"providers": Evil(), 1: "x", "count": 10 ** 30}, "x")
    assert out == {"_dropped": 3}
    assert filter_details("not a mapping") == {"_dropped": 1}


@pytest.mark.parametrize("key", ["password", "user_password", "PassWd", "client-secret",
                                 "access_token", "Authorization", "set-cookie", "dek",
                                 "wrapped_dek", "private_key", "apiKey", "totp", "otp_code",
                                 "seed", "filename", "fileName", "username", "email",
                                 "content", "plaintext"])
def test_deny_key_patterns(key):
    assert is_sensitive_key(key)


@pytest.mark.parametrize("key", sorted(GLOBAL_ALLOWED_DETAIL_KEYS))
def test_allow_list_contains_no_denied_name(key):
    assert not is_sensitive_key(key)


@pytest.mark.parametrize("value", [JWT, f"Bearer {JWT}", "bearer abcdefgh123", PEM, HEX_KEY,
                                   B64_KEY, EMAIL, "password=hunter2", "token: abc"])
def test_sensitive_values(value):
    assert looks_sensitive(value)


@pytest.mark.parametrize("value", ["mfa-required", "not-owner", "provider-unavailable",
                                   "ProviderTimeout", "file:read", "aws-s3",
                                   "integrity-failure-on-replica-two-after-three-retries",
                                   "8f14e45fceea167a5a36dedd4bea2543"])
def test_ordinary_values_not_redacted(value):
    assert not looks_sensitive(value)


def test_actor_is_pseudonymous_and_stable(service, attacker):
    service.record(event_type="a.b", action="x", outcome="success", actor_id="user-1")
    service.record(event_type="a.b", action="x", outcome="success", actor_id="user-1")
    service.record(event_type="a.b", action="x", outcome="success", actor_id="user-2")
    actors = [r[0] for r in attacker().execute("SELECT actor FROM audit_events ORDER BY seq")]
    assert actors[0] == actors[1] != actors[2]
    assert all(a.startswith("u_") and len(a) == 34 for a in actors)
    assert "user-1" not in actors[0] and "user-2" not in actors[2]
    assert actors[0] == service.pseudonym_for("user-1")
    assert service.record(event_type="a.b", action="x", outcome="success").seq == 4
    assert service.get_event(4)["actor"] is None


def test_pseudonym_depends_on_key(make_service, kms):
    from app.contracts import KeyPurpose
    svc = make_service()
    before = svc.pseudonym_for("user-1")
    kms.rotate(KeyPurpose.AUDIT_PSEUDONYM)
    assert svc.pseudonym_for("user-1") != before   # rotation breaks linkability (ADR-0007)


@pytest.mark.parametrize("ip,expected", [
    ("203.0.113.77", "203.0.113.0/24"),
    ("10.1.2.3", "10.1.2.0/24"),
    ("2001:db8:abcd:12::99", "2001:db8:abcd::/48"),
    ("[2001:db8:abcd:12::99]", "2001:db8:abcd::/48"),
    ("fe80::1%eth0", "fe80::/48"),
    ("::ffff:198.51.100.9", "198.51.100.0/24"),
    ("not-an-ip", None), ("", None), (None, None), ("1.2.3.4:5678", None),
    ("999.1.1.1", None), ("1.2.3.4; DROP TABLE", None),
])
def test_ip_generalisation(ip, expected):
    assert generalise_ip(ip, 24, 48) == expected


def test_ip_prefix_configurable(make_service):
    svc = make_service(audit_ip_prefix_v4=16, audit_ip_prefix_v6=32)
    svc.record(event_type="a.b", action="x", outcome="success", source_ip="203.0.113.77")
    svc.record(event_type="a.b", action="x", outcome="success", source_ip="2001:db8:abcd::1")
    svc.record(event_type="a.b", action="x", outcome="success", source_ip="garbage")
    assert [svc.get_event(i)["source_net"] for i in (1, 2, 3)] == \
        ["203.0.0.0/16", "2001:db8::/32", None]


def test_details_stored_as_canonical_json(service, attacker):
    service.record(event_type="a.b", action="x", outcome="success",
                   details={"count": 1, "chunk_index": 0, "role": "ü"})
    raw = attacker().execute("SELECT details FROM audit_events").fetchone()[0]
    assert raw == '{"chunk_index":0,"count":1,"role":"\\u00fc"}'
    assert json.loads(raw)["role"] == "ü"
