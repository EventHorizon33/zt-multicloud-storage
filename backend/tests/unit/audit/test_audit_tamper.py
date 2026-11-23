"""Tamper detection. Every attack edits the audit DB directly with raw SQL
through a second connection, as an attacker with DB access would."""
from __future__ import annotations

import json
import sqlite3

from app.audit.chain import compute_hash

from ._fakes import fill

COLS = ("seq, id, ts, event_type, action, outcome, severity, actor, actor_role, resource_type, "
        "resource_id, reason, details, request_id, source_net, prev_hash, hash")


def _row(db, seq) -> dict:
    db.row_factory = sqlite3.Row
    r = db.execute("SELECT * FROM audit_events WHERE seq=?", (seq,)).fetchone()
    db.row_factory = None
    return dict(r)


def _types(report) -> set[str]:
    return {f.type for f in report.findings}


def _at(report, ftype) -> set:
    return {f.seq for f in report.findings if f.type == ftype}


def test_modify_field_detected_as_record_modified(service, attacker):
    fill(service, 20, outcome="denied")
    db = attacker()
    db.execute("UPDATE audit_events SET outcome='success' WHERE seq=7")
    report = service.verify_chain()
    assert not report.ok
    assert _at(report, "record-modified") == {7}
    assert "chain-broken" not in _types(report)       # stored hash still links


def test_modify_and_recompute_own_hash_breaks_next_link(service, attacker):
    fill(service, 20, outcome="denied")
    db = attacker()
    row = _row(db, 7)
    row["outcome"] = "success"
    new_hash = compute_hash(row)
    db.execute("UPDATE audit_events SET outcome='success', hash=? WHERE seq=7", (new_hash,))
    report = service.verify_chain()
    assert not report.ok
    assert 7 not in _at(report, "record-modified")
    assert _at(report, "chain-broken") == {8}


def test_delete_middle_record(service, attacker):
    fill(service, 20)
    attacker().execute("DELETE FROM audit_events WHERE seq=10")
    report = service.verify_chain()
    assert not report.ok
    assert _at(report, "sequence-gap") == {10}
    assert _at(report, "chain-broken") == {11}


def test_reports_all_findings_not_just_first(service, attacker):
    fill(service, 30)
    db = attacker()
    db.execute("UPDATE audit_events SET reason='x' WHERE seq=3")
    db.execute("DELETE FROM audit_events WHERE seq=15")
    db.execute("UPDATE audit_events SET action='file:list' WHERE seq=25")
    report = service.verify_chain()
    assert _at(report, "record-modified") == {3, 25}
    assert _at(report, "sequence-gap") == {15}


def test_swap_two_records_detected_as_reordered(service, attacker):
    fill(service, 20)
    db = attacker()
    # move rows 5 and 6 into each other's position (all content swapped, seq kept)
    db.execute("UPDATE audit_events SET seq=-5 WHERE seq=5")
    db.execute("UPDATE audit_events SET seq=5 WHERE seq=6")
    db.execute("UPDATE audit_events SET seq=6 WHERE seq=-5")
    report = service.verify_chain()
    assert not report.ok
    assert {5, 6} <= _at(report, "record-modified")    # seq is part of the hash
    assert "chain-broken" in _types(report)
    assert "reordered" in _types(report)


def test_swap_seq_and_recompute_hashes_still_detected(service, attacker):
    fill(service, 20)
    db = attacker()
    a, b = _row(db, 5), _row(db, 6)
    a["seq"], b["seq"] = 6, 5
    db.execute("DELETE FROM audit_events WHERE seq IN (5,6)")
    for r in (a, b):
        r["hash"] = compute_hash(r)
        db.execute(f"INSERT INTO audit_events ({COLS}) VALUES ({','.join('?' * 17)})",
                   tuple(r[c.strip()] for c in COLS.split(",")))
    report = service.verify_chain()
    assert not report.ok
    assert "record-modified" not in _types(report)
    assert _at(report, "chain-broken") & {5, 6, 7}


def test_insert_forged_record_in_middle(service, attacker):
    fill(service, 20)
    db = attacker()
    # shift 11..20 up by one and forge a record at 11 that links correctly to 10
    for s in range(20, 10, -1):
        db.execute("UPDATE audit_events SET seq=? WHERE seq=?", (s + 1, s))
    forged = _row(db, 10)
    forged.update(seq=11, id="f" * 32, outcome="success", prev_hash=forged["hash"])
    forged["hash"] = compute_hash(forged)
    db.execute(f"INSERT INTO audit_events ({COLS}) VALUES ({','.join('?' * 17)})",
               tuple(forged[c.strip()] for c in COLS.split(",")))
    report = service.verify_chain()
    assert not report.ok
    # the forged record itself hashes fine; the shifted originals do not
    assert 11 not in _at(report, "record-modified")
    assert set(range(12, 22)) <= _at(report, "record-modified")
    assert 12 in _at(report, "chain-broken")


def test_truncate_tail_after_checkpoint(make_service, attacker):
    svc = make_service(audit_checkpoint_every=10)
    fill(svc, 25)                              # checkpoints at 10, 20
    attacker().execute("DELETE FROM audit_events WHERE seq > 15")
    report = svc.verify_chain()
    assert not report.ok
    assert _at(report, "truncated") == {20}


def test_truncate_tail_and_delete_checkpoints_detected_via_anchors(make_service, attacker, anchors):
    svc = make_service(audit_checkpoint_every=10)
    fill(svc, 25)
    db = attacker()
    db.execute("DELETE FROM audit_events WHERE seq > 15")
    db.execute("DELETE FROM audit_checkpoints")
    report = svc.verify_chain()
    assert not report.ok
    assert _at(report, "truncated") == {20}
    assert {10, 20} <= _at(report, "checkpoint-missing")
    # without anchors the same attack would be invisible: that is the point of anchoring
    assert svc.verify_chain(check_anchors=False).ok


def test_truncate_everything_detected_via_anchors(make_service, attacker):
    svc = make_service(audit_checkpoint_every=10)
    fill(svc, 25)
    db = attacker()
    db.execute("DELETE FROM audit_events")
    db.execute("DELETE FROM audit_checkpoints")
    report = svc.verify_chain()
    assert not report.ok and _at(report, "truncated") == {10, 20}


def test_rewrite_whole_tail_with_valid_chain_detected_by_checkpoint(make_service, attacker):
    svc = make_service(audit_checkpoint_every=10)
    fill(svc, 25, outcome="denied")
    db = attacker()
    prev_hash = _row(db, 4)["hash"]
    for s in range(5, 26):                       # rewrite 5..25, recomputing every hash
        r = _row(db, s)
        r["outcome"] = "success"
        r["prev_hash"] = prev_hash
        r["hash"] = compute_hash(r)
        db.execute("UPDATE audit_events SET outcome=?, prev_hash=?, hash=? WHERE seq=?",
                   (r["outcome"], r["prev_hash"], r["hash"], s))
        prev_hash = r["hash"]
    report = svc.verify_chain()
    assert not report.ok
    assert "record-modified" not in _types(report) and "chain-broken" not in _types(report)
    assert _at(report, "checkpoint-mismatch") == {10, 20}


def test_rewrite_after_last_checkpoint_is_the_stated_limit(make_service, attacker):
    """Documented limit: events after the last checkpoint can be rewritten (or
    truncated) consistently without detection until the next checkpoint."""
    svc = make_service(audit_checkpoint_every=10)
    fill(svc, 25)
    db = attacker()
    db.execute("DELETE FROM audit_events WHERE seq > 22")
    assert svc.verify_chain().ok


def test_tampered_checkpoint_signature_and_head(make_service, attacker):
    svc = make_service(audit_checkpoint_every=10, use_anchors=False)
    fill(svc, 30)
    db = attacker()
    sig = db.execute("SELECT signature FROM audit_checkpoints WHERE seq=10").fetchone()[0]
    flipped = ("0" if sig[0] != "0" else "1") + sig[1:]
    db.execute("UPDATE audit_checkpoints SET signature=? WHERE seq=10", (flipped,))
    db.execute("UPDATE audit_checkpoints SET head_hash=? WHERE seq=20", ("ab" * 32,))
    report = svc.verify_chain()
    assert not report.ok
    assert _at(report, "checkpoint-signature-invalid") == {10, 20}


def test_attacker_cannot_forge_new_checkpoint_without_key(make_service, attacker, kms):
    """Rewriting history and re-signing requires the signing key."""
    svc = make_service(audit_checkpoint_every=10, use_anchors=False)
    fill(svc, 20)
    db = attacker()
    db.execute("UPDATE audit_checkpoints SET seq=5 WHERE seq=20")
    report = svc.verify_chain()
    assert "checkpoint-signature-invalid" in _types(report)


def test_anchor_copy_tampered_on_one_provider(make_service, anchors):
    svc = make_service(audit_checkpoint_every=10)
    fill(svc, 20)
    key = f"anchors/audit/{svc.log_id}/checkpoint-000000000010.json"
    doc = json.loads(anchors.objects["gcs"][key])
    payload = json.loads(doc["payload"])
    payload["head_hash"] = "cd" * 32
    doc["payload"] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    anchors.objects["gcs"][key] = json.dumps(doc).encode()
    report = svc.verify_chain()
    assert not report.ok
    mism = [f for f in report.findings if f.type == "anchor-mismatch"]
    assert mism and all(f.seq == 10 and "gcs" in f.detail for f in mism)
    assert report.anchors_checked == 6


def test_anchor_missing_on_one_provider_is_informational(make_service, anchors):
    svc = make_service(audit_checkpoint_every=10)
    fill(svc, 20)
    del anchors.objects["azure-blob"][f"anchors/audit/{svc.log_id}/checkpoint-000000000010.json"]
    report = svc.verify_chain()
    assert report.ok
    assert [f.seq for f in report.findings if f.type == "anchor-missing"] == [10]


def test_signing_key_rotation_old_checkpoints_still_verify(make_service, kms):
    from app.contracts import KeyPurpose
    svc = make_service(audit_checkpoint_every=10)
    fill(svc, 10)
    kms.rotate(KeyPurpose.AUDIT_SIGNING)
    fill(svc, 10)
    kms.rotate(KeyPurpose.AUDIT_SIGNING)
    fill(svc, 10)
    versions = sorted(cp.key_version for cp in svc.list_checkpoints())
    assert versions == [1, 2, 3]
    report = svc.verify_chain()
    assert report.ok, report.findings
    assert report.checkpoints_checked == 3 and report.anchors_checked == 9


def test_verify_partial_range(service, attacker):
    fill(service, 40)
    attacker().execute("UPDATE audit_events SET outcome='error' WHERE seq=30")
    assert service.verify_chain(from_seq=5, to_seq=20).ok
    r = service.verify_chain(from_seq=21, to_seq=35)
    assert {f.seq for f in r.findings if f.type == "record-modified"} == {30}
    assert r.first_seq == 21 and r.last_seq == 35
