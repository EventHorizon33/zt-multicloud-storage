"""Recording, hash-chain structure, export."""
from __future__ import annotations

import hashlib
import json

from app.audit.chain import GENESIS_HASH, canonical_json, compute_hash
from app.audit.records import AuditRecord
from app.contracts import AuditSink, Outcome, Severity

from ._fakes import fill


def test_service_satisfies_audit_sink_protocol(service):
    assert isinstance(service, AuditSink)


def test_record_persists_fields_and_links_chain(service, attacker):
    r1 = service.record(event_type="auth.login", action="auth:login", outcome=Outcome.SUCCESS,
                        actor_id="user-1", actor_role="user", resource_type="session",
                        resource_id="s123", reason="ok", details={"mfa": True, "method": "totp"},
                        request_id="req-1", source_ip="203.0.113.77")
    r2 = service.record(event_type="file.download", action="file:read", outcome="denied",
                        severity=Severity.WARNING, actor_id="user-2", resource_id="f1")
    assert isinstance(r1, AuditRecord)
    assert (r1.seq, r2.seq) == (1, 2)
    assert r1.prev_hash == GENESIS_HASH and r2.prev_hash == r1.hash

    db = attacker()
    db.row_factory = __import__("sqlite3").Row
    rows = [dict(r) for r in db.execute("SELECT * FROM audit_events ORDER BY seq")]
    first = rows[0]
    assert first["event_type"] == "auth.login" and first["action"] == "auth:login"
    assert first["outcome"] == "success" and first["severity"] == "info"
    assert first["actor"] == service.pseudonym_for("user-1")
    assert first["actor_role"] == "user" and first["resource_type"] == "session"
    assert first["resource_id"] == "s123" and first["reason"] == "ok"
    assert json.loads(first["details"]) == {"mfa": True, "method": "totp"}
    assert first["request_id"] == "req-1" and first["source_net"] == "203.0.113.0/24"
    assert first["ts"].endswith("Z") and len(first["ts"]) == 27
    # recompute the hash independently of the library
    material = {k: v for k, v in first.items() if k != "hash"}
    expected = hashlib.sha256(bytes.fromhex(GENESIS_HASH) + canonical_json(material).encode()).hexdigest()
    assert first["hash"] == expected == compute_hash(first)
    assert rows[1]["outcome"] == "denied" and rows[1]["severity"] == "warning"
    assert rows[1]["prev_hash"] == first["hash"]


def test_seq_strictly_monotonic_and_clean_log_verifies(service):
    recs = fill(service, 25)
    assert [r.seq for r in recs] == list(range(1, 26))
    report = service.verify_chain()
    assert report.ok, report.findings
    assert report.events_checked == 25 and report.first_seq == 1 and report.last_seq == 25
    assert report.head_hash == recs[-1].hash and report.findings == []


def test_empty_log_verifies(service):
    report = service.verify_chain()
    assert report.ok and report.events_checked == 0 and report.last_seq is None


def test_invalid_outcome_or_severity_rejected(service):
    import pytest
    with pytest.raises(ValueError):
        service.record(event_type="x.y", action="a", outcome="maybe")
    with pytest.raises(ValueError):
        service.record(event_type="x.y", action="a", outcome="success", severity="loud")
    with pytest.raises(ValueError):
        service.record(event_type="", action="a", outcome="success")


def test_export_ndjson_is_offline_verifiable(service):
    fill(service, 30)
    lines = list(service.export_ndjson(5, 20))
    assert len(lines) == 16
    prev = None
    for line in lines:
        rec = json.loads(line)
        material = {k: v for k, v in rec.items() if k != "hash"}
        h = hashlib.sha256(bytes.fromhex(rec["prev_hash"]) + canonical_json(material).encode()).hexdigest()
        assert h == rec["hash"]
        if prev is not None:
            assert rec["prev_hash"] == prev["hash"] and rec["seq"] == prev["seq"] + 1
        prev = rec
    assert len(list(service.export_ndjson())) == 30


def test_audit_record_survives_business_rollback(tmp_path, service):
    """The audit DB is separate: a rolled-back business transaction elsewhere
    cannot take the audit record with it."""
    import sqlite3
    biz = sqlite3.connect(str(tmp_path / "metadata.db"))
    biz.execute("CREATE TABLE t (x)")
    biz.execute("BEGIN")
    biz.execute("INSERT INTO t VALUES (1)")
    service.record(event_type="file.delete", action="file:delete", outcome="failure")
    biz.rollback()
    biz.close()
    assert service.get_event(1)["outcome"] == "failure"
