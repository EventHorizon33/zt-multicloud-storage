"""Retention: pruning behind a signed checkpoint vs. malicious deletion."""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.audit import AuditContext, AuditIntegrityError

from ._fakes import fill


def _setup(make_service, clock, **kw):
    svc = make_service(audit_retention_days=30, **kw)
    fill(svc, 20)                         # "old" events
    clock.advance(timedelta(days=40))
    fill(svc, 10)                         # recent events: seq 21..30
    return svc


def test_retention_deletes_old_prefix_and_still_verifies(make_service, clock, anchors):
    svc = _setup(make_service, clock)
    res = svc.apply_retention()
    assert (res.deleted, res.kept, res.new_first_seq, res.checkpoint_seq) == (20, 10, 21, 20)
    assert svc.get_event(20) is None and svc.get_event(21) is not None
    rcp = [c for c in svc.list_checkpoints() if c.kind == "retention"][0]
    assert rcp.seq == 20 and rcp.first_seq == 1 and rcp.event_count == 20
    assert f"anchors/audit/{svc.log_id}/retention-000000000020.json" in anchors.objects["aws-s3"]
    report = svc.verify_chain()
    assert report.ok, report.findings
    assert report.first_seq == 21 and report.events_checked == 10
    # appending after retention continues the same chain
    fill(svc, 3)
    assert svc.verify_chain().ok and svc.get_event(33) is not None


def test_retention_prunes_old_non_retention_checkpoints(make_service, clock, attacker):
    svc = _setup(make_service, clock, audit_checkpoint_every=7)   # cps at 7, 14, 21, 28
    svc.apply_retention()
    rows = attacker().execute("SELECT seq, kind FROM audit_checkpoints ORDER BY seq").fetchall()
    assert rows == [(20, "retention"), (21, "periodic"), (28, "periodic")]
    # old anchors (7, 14) remain on providers; they are below the retained range
    assert svc.verify_chain().ok


def test_malicious_delete_after_retention_detected(make_service, clock, attacker):
    svc = _setup(make_service, clock)
    svc.apply_retention()
    attacker().execute("DELETE FROM audit_events WHERE seq=21")
    report = svc.verify_chain()
    assert not report.ok
    assert [f.seq for f in report.findings if f.type == "genesis-invalid"] == [22]


def test_malicious_prefix_delete_without_retention_detected(make_service, attacker):
    svc = make_service()
    fill(svc, 10)
    attacker().execute("DELETE FROM audit_events WHERE seq <= 3")
    report = svc.verify_chain()
    assert [f.seq for f in report.findings if f.type == "genesis-invalid"] == [4]


def test_deleting_retention_checkpoint_row_detected_without_anchor(make_service, clock, attacker):
    svc = _setup(make_service, clock, use_anchors=False)
    svc.apply_retention()
    attacker().execute("DELETE FROM audit_checkpoints WHERE kind='retention'")
    assert "genesis-invalid" in {f.type for f in svc.verify_chain().findings}


def test_deleting_retention_checkpoint_row_recovered_from_anchor(make_service, clock, attacker):
    svc = _setup(make_service, clock)
    svc.apply_retention()
    attacker().execute("DELETE FROM audit_checkpoints WHERE kind='retention'")
    report = svc.verify_chain()
    types = {f.type for f in report.findings}
    assert "genesis-invalid" not in types          # boundary re-established from the anchor
    assert "checkpoint-missing" in types and not report.ok


def test_retention_disabled_when_days_le_zero(make_service, clock):
    for days in (0, -1):
        svc = make_service(audit_retention_days=days, db_name=f"a{days}.db")
        fill(svc, 5)
        clock.advance(timedelta(days=1000))
        res = svc.apply_retention()
        assert (res.deleted, res.kept, res.checkpoint_seq) == (0, 5, None)


def test_retention_nothing_old_enough(make_service, clock):
    svc = make_service(audit_retention_days=30)
    fill(svc, 5)
    res = svc.apply_retention()
    assert (res.deleted, res.kept, res.new_first_seq, res.checkpoint_seq) == (0, 5, 1, None)


def test_retention_stops_at_first_young_event(make_service, clock, attacker):
    """Events are only cut as a prefix that is entirely older than the cutoff."""
    svc = make_service(audit_retention_days=30)
    fill(svc, 5)
    clock.advance(timedelta(days=40))
    fill(svc, 5)
    res = svc.apply_retention(now=clock.now)
    assert res.checkpoint_seq == 5 and res.deleted == 5


def test_retention_everything_then_append(make_service, clock):
    svc = make_service(audit_retention_days=30)
    fill(svc, 5)
    clock.advance(timedelta(days=40))
    res = svc.apply_retention()
    assert (res.deleted, res.kept, res.new_first_seq) == (5, 0, None)
    assert svc.verify_chain().ok
    rec = fill(svc, 1)[0]
    assert rec.seq == 6
    assert svc.verify_chain().ok


def test_retention_refuses_when_prefix_tampered(make_service, clock, attacker):
    svc = _setup(make_service, clock)
    attacker().execute("UPDATE audit_events SET outcome='denied' WHERE seq=3")
    ctx = AuditContext(actor_id="admin")
    with pytest.raises(AuditIntegrityError):
        svc.apply_retention(audit_context=ctx)
    assert svc.get_event(3) is not None            # evidence preserved
    last = svc.search(event_type="audit.retention")[0][0]
    assert last["outcome"] == "failure" and last["severity"] == "critical"


def test_retention_is_audited(make_service, clock):
    svc = _setup(make_service, clock)
    svc.apply_retention(audit_context=AuditContext(actor_id="admin", actor_role="admin"))
    ev = svc.search(event_type="audit.retention")[0][0]
    assert ev["details"]["deleted"] == 20 and ev["details"]["seq"] == 20
    assert svc.verify_chain().ok


def test_second_retention_run(make_service, clock):
    svc = _setup(make_service, clock)
    svc.apply_retention()
    clock.advance(timedelta(days=40))
    fill(svc, 5)                                       # 31..35
    res = svc.apply_retention()
    assert res.checkpoint_seq == 30 and res.deleted == 10 and res.new_first_seq == 31
    assert svc.verify_chain().ok
