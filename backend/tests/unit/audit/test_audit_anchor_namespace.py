"""Finding F4 / ADR-0006 amendment: anchors are namespaced per audit log, so
deployments sharing a bucket cannot overwrite or confuse each other's anchors."""
from __future__ import annotations

import hashlib
import sqlite3

from app.audit import build_audit_service
from app.config import Settings
from app.contracts import KeyPurpose

from ._fakes import FakeKMS, fill


def _service(tmp_path, name, kms, anchors, clock, every=10):
    settings = Settings(data_dir=tmp_path, audit_database_url=f"sqlite:///{tmp_path / name}",
                        audit_checkpoint_every=every, audit_retention_days=365)
    return build_audit_service(settings, kms, anchors, clock)


def test_log_id_is_derived_from_signing_key_v1_and_stable_across_rotation(make_service, kms):
    svc = make_service()
    pem = kms.public_key_pem(purpose=KeyPurpose.AUDIT_SIGNING, version=1)
    assert svc.log_id == hashlib.sha256(pem).hexdigest()[:16]
    kms.rotate(KeyPurpose.AUDIT_SIGNING)
    assert make_service(db_name="other.db").log_id == svc.log_id


def test_two_deployments_sharing_a_bucket_do_not_collide(tmp_path, anchors, clock):
    a = _service(tmp_path, "a.db", FakeKMS(), anchors, clock)
    b = _service(tmp_path, "b.db", FakeKMS(), anchors, clock)
    assert a.log_id != b.log_id
    fill(a, 25)
    fill(b, 25)                                   # same seqs 10 and 20 as a
    keys = set(anchors.objects["gcs"])
    for svc in (a, b):
        assert {f"anchors/audit/{svc.log_id}/checkpoint-{s:012d}.json" for s in (10, 20)} <= keys
    for svc in (a, b):
        rep = svc.verify_chain()
        assert rep.ok, rep.findings
        assert rep.anchors_checked == 6           # its own 2 checkpoints x 3 providers only


def test_foreign_and_legacy_anchors_are_ignored(make_service, anchors):
    svc = make_service(audit_checkpoint_every=10)
    fill(svc, 20)
    junk = b'{"not": "an anchor"}'
    for store in anchors.objects.values():
        store["anchors/audit/checkpoint-000000000010.json"] = junk                 # pre-F4 key format
        store["anchors/audit/0123456789abcdef/checkpoint-000000000010.json"] = junk  # another log
        store["anchors/audit/0123456789abcdef/checkpoint-000000099999.json"] = junk
    rep = svc.verify_chain()
    assert rep.ok and rep.findings == [] and rep.anchors_checked == 6


def test_truncation_still_detected_from_own_namespace_after_db_wipe(make_service, tmp_path, kms, anchors):
    svc = make_service(audit_checkpoint_every=10)
    fill(svc, 25)
    conn = sqlite3.connect(tmp_path / "audit.db", isolation_level=None)
    conn.execute("DELETE FROM audit_events WHERE seq > 5")
    conn.execute("DELETE FROM audit_checkpoints")
    conn.close()
    rep = svc.verify_chain()
    assert not rep.ok and "truncated" in rep.finding_types()
    # a fresh service on the wiped DB (same KMS) still lands in the same namespace
    assert make_service(db_name="audit.db").log_id == svc.log_id
