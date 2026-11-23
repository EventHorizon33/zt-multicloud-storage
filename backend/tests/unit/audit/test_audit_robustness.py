"""Concurrency, write failure, performance sanity."""
from __future__ import annotations

import threading
import time

import pytest

from app.audit import AuditWriteError

from ._fakes import fill


def test_concurrent_appends_never_fork_the_chain(make_service, attacker):
    svc = make_service(audit_checkpoint_every=100)
    errors: list[BaseException] = []
    barrier = threading.Barrier(16)

    def worker(n: int) -> None:
        try:
            barrier.wait()
            for i in range(50):
                svc.record(event_type="file.download", action="file:read", outcome="success",
                           actor_id=f"user-{n}", details={"chunk_index": i})
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    seqs = [r[0] for r in attacker().execute("SELECT seq FROM audit_events ORDER BY seq")]
    assert seqs == list(range(1, 801))
    report = svc.verify_chain()
    assert report.ok, report.findings[:5]
    assert sorted(c.seq for c in svc.list_checkpoints()) == list(range(100, 801, 100))


def test_two_service_instances_on_one_db_do_not_fork(make_service):
    """Two instances (as two processes would have) share no process lock; the
    DB write lock (BEGIN IMMEDIATE) alone must serialise them."""
    a = make_service()
    b = make_service()

    def run(svc):
        for _ in range(100):
            svc.record(event_type="x.y", action="a", outcome="success")

    ts = [threading.Thread(target=run, args=(s,)) for s in (a, b, a, b)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    report = a.verify_chain()
    assert report.ok and report.last_seq == 400


def test_record_raises_when_table_dropped(service, attacker):
    fill(service, 2)
    attacker().execute("DROP TABLE audit_events")
    with pytest.raises(AuditWriteError) as exc:
        service.record(event_type="file.download", action="file:read", outcome="success",
                       details={"size_bytes": 1}, reason="sensitive-reason-text")
    # the error message carries no SQL, parameters or event content
    assert "sensitive-reason-text" not in str(exc.value)
    assert exc.value.__cause__ is None and exc.value.__suppress_context__


def test_record_raises_when_database_unwritable(service, attacker):
    fill(service, 1)
    db = attacker()
    db.execute("BEGIN EXCLUSIVE")         # hold the write lock past the busy timeout
    service.engine.dispose()
    import sqlalchemy
    # shorten the busy timeout for this test only
    @sqlalchemy.event.listens_for(service.engine, "connect")
    def _short(dbapi_conn, _):
        dbapi_conn.execute("PRAGMA busy_timeout=200")
    try:
        with pytest.raises(AuditWriteError):
            service.record(event_type="x.y", action="a", outcome="success")
    finally:
        db.execute("ROLLBACK")
    assert service.record(event_type="x.y", action="a", outcome="success").seq == 2


def test_record_raises_when_kms_pseudonym_fails(service, kms):
    def boom(*a, **k):
        raise RuntimeError("kms down")
    kms.mac = boom
    with pytest.raises(AuditWriteError):
        service.record(event_type="x.y", action="a", outcome="success", actor_id="u1")


def test_verify_20k_events_performance(make_service, capsys):
    """Sanity check only. The chain is built in batches of 100 rows per
    transaction (same hash function, same columns) with a signed, anchored
    checkpoint after each batch through the public API, because 20k
    individually fsynced appends would dominate the test time; append
    throughput is measured separately on 1000 real record() calls."""
    from sqlalchemy import insert
    from app.audit.chain import compute_hash
    from app.audit.models import EVENTS
    import uuid

    svc = make_service(audit_checkpoint_every=0)
    t0 = time.perf_counter()
    fill(svc, 1000)
    t_append = time.perf_counter() - t0

    prev, base = svc.get_event(1000)["hash"], svc.get_event(1000)["ts"]
    seq = 1000
    while seq < 20_000:
        rows = []
        for _ in range(100):
            seq += 1
            r = {"seq": seq, "id": uuid.uuid4().hex, "ts": base, "event_type": "file.download",
                 "action": "file:read", "outcome": "success", "severity": "info",
                 "actor": svc.pseudonym_for(f"user-{seq % 50}"), "actor_role": "user",
                 "resource_type": "file", "resource_id": f"f{seq}",
                 "reason": None, "details": '{"size_bytes":%d}' % seq, "request_id": None,
                 "source_net": "203.0.113.0/24", "prev_hash": prev}
            r["hash"] = compute_hash(r)
            prev = r["hash"]
            rows.append(r)
        with svc.engine.connect() as conn:
            conn.exec_driver_sql("BEGIN IMMEDIATE")
            conn.execute(insert(EVENTS), rows)
            conn.commit()
        svc.create_checkpoint(kind="periodic")
    t1 = time.perf_counter()
    report = svc.verify_chain()
    t_verify = time.perf_counter() - t1
    assert report.ok, report.findings[:3]
    assert report.events_checked == 20_000 and report.checkpoints_checked == 190
    assert report.anchors_checked == 570
    with capsys.disabled():
        print(f"\n[audit perf] 1000 record() calls: {t_append:.2f}s "
              f"({1000 / t_append:.0f}/s); verify_chain 20000 events + 190 checkpoints "
              f"+ 570 anchor copies: {t_verify:.2f}s")
    assert t_verify < 120          # sanity only, not a tight bound
