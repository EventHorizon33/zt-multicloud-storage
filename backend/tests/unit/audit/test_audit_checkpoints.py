"""Periodic/manual checkpoints, anchors, failure isolation, audited housekeeping."""
from __future__ import annotations

import json

import pytest

from app.audit import AuditContext, AuditError
from app.audit.chain import canonical_json
from app.contracts import KeyPurpose

from ._fakes import fill


def test_periodic_checkpoint_every_n(make_service, kms):
    svc = make_service(audit_checkpoint_every=10)
    recs = fill(svc, 35)
    cps = sorted(svc.list_checkpoints(), key=lambda c: c.seq)
    assert [c.seq for c in cps] == [10, 20, 30]
    assert all(c.kind == "periodic" for c in cps)
    for cp in cps:
        assert cp.head_hash == recs[cp.seq - 1].hash
        assert cp.first_seq == 1 and cp.event_count == cp.seq
        assert kms.verify(cp.payload().encode(), bytes.fromhex(cp.signature),
                          purpose=KeyPurpose.AUDIT_SIGNING, key_id=cp.key_id,
                          version=cp.key_version)


def test_anchors_written_to_all_providers(make_service, anchors, kms):
    svc = make_service(audit_checkpoint_every=10)
    fill(svc, 20)
    ns = f"anchors/audit/{svc.log_id}/"            # per-log namespace (F4, ADR-0006)
    for prov, objects in anchors.objects.items():
        assert sorted(objects) == [ns + "checkpoint-000000000010.json", ns + "checkpoint-000000000020.json"]
    cp = [c for c in svc.list_checkpoints() if c.seq == 20][0]
    assert cp.anchors == {"aws-s3": True, "azure-blob": True, "gcs": True}
    doc = json.loads(anchors.objects["gcs"][ns + "checkpoint-000000000020.json"])
    assert set(doc) == {"v", "alg", "payload", "signature", "key_id", "key_version"}
    payload = json.loads(doc["payload"])
    assert payload == {"v": 1, "seq": 20, "head_hash": cp.head_hash, "ts": cp.ts,
                       "event_count": 20, "first_seq": 1, "kind": "periodic"}
    assert canonical_json(payload) == doc["payload"]
    assert kms.verify(doc["payload"].encode(), bytes.fromhex(doc["signature"]),
                      purpose=KeyPurpose.AUDIT_SIGNING, key_id=doc["key_id"],
                      version=doc["key_version"])


def test_anchor_store_failure_does_not_break_record(make_service, anchors):
    svc = make_service(audit_checkpoint_every=5)
    anchors.raise_on_put = True
    recs = fill(svc, 10)
    assert recs[-1].seq == 10
    cps = svc.list_checkpoints()
    assert sorted(c.seq for c in cps) == [5, 10]
    assert all(not any(c.anchors.values()) for c in cps)
    assert svc.anchor_failures == 2
    report = svc.verify_chain()
    assert report.ok                     # missing anchors are informational
    assert {f.type for f in report.findings} == {"anchor-missing"}


def test_one_provider_down_recorded_per_provider(make_service, anchors):
    svc = make_service(audit_checkpoint_every=5)
    anchors.down.add("azure-blob")
    fill(svc, 5)
    cp = svc.list_checkpoints()[0]
    assert cp.anchors == {"aws-s3": True, "azure-blob": False, "gcs": True}


def test_signing_failure_does_not_lose_event_and_is_retried(make_service, kms):
    svc = make_service(audit_checkpoint_every=5)
    kms.fail_sign = True
    fill(svc, 6)
    assert svc.checkpoint_failures == 2 and svc.list_checkpoints() == []
    assert svc.get_event(6) is not None
    kms.fail_sign = False
    fill(svc, 1)                          # next append catches up
    assert [c.seq for c in svc.list_checkpoints()] == [7]


def test_anchoring_can_be_disabled(make_service, anchors):
    svc = make_service(audit_checkpoint_every=5, audit_anchor_checkpoints=False)
    fill(svc, 5)
    assert all(not o for o in anchors.objects.values())
    assert svc.list_checkpoints()[0].anchors == {}


def test_manual_checkpoint_and_audited_housekeeping(make_service):
    svc = make_service()
    fill(svc, 7)
    ctx = AuditContext(actor_id="admin-1", actor_role="admin", request_id="rq",
                       source_ip="198.51.100.4")
    cp = svc.create_checkpoint(audit_context=ctx)
    assert cp.kind == "manual" and cp.seq == 7 and cp.event_count == 7
    ev = svc.get_event(8)
    assert ev["event_type"] == "audit.checkpoint" and ev["action"] == "audit:checkpoint"
    assert ev["actor"] == svc.pseudonym_for("admin-1") and ev["source_net"] == "198.51.100.0/24"
    assert ev["details"]["seq"] == 7 and ev["details"]["kind"] == "manual"
    assert ev["details"]["providers"] == ["aws-s3", "azure-blob", "gcs"]
    report = svc.verify_chain(audit_context=ctx)
    assert report.ok
    v = svc.get_event(9)
    assert v["event_type"] == "audit.verify" and v["outcome"] == "success"
    assert v["details"]["events_checked"] == 8 and v["details"]["ok"] is True


def test_failed_verification_is_recorded_as_critical(service, attacker):
    fill(service, 5)
    attacker().execute("UPDATE audit_events SET outcome='denied' WHERE seq=2")
    service.verify_chain(audit_context=AuditContext(actor_id="auditor-1"))
    ev = service.get_event(6)
    assert ev["outcome"] == "failure" and ev["severity"] == "critical"
    assert ev["details"]["finding_types"] == ["record-modified"]


def test_checkpoint_on_empty_log_refused(service):
    with pytest.raises(AuditError):
        service.create_checkpoint()
    with pytest.raises(ValueError):
        service.create_checkpoint(kind="bogus")


def test_max_findings_caps_list_but_not_verdict(service, attacker):
    fill(service, 30)
    attacker().execute("UPDATE audit_events SET outcome='error'")
    r = service.verify_chain(max_findings=5)
    assert not r.ok and len(r.findings) == 5 and r.findings_truncated
