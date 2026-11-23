import hashlib
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.contracts import Outcome, ProviderTimeout, Severity, StorageError
from app.storage import (
    ChunkStoreError,
    ChunkUnavailableError,
    FaultInjectionDisabled,
    InvalidObjectKey,
    RetryPolicy,
    RotatingPlacement,
    StorageOrchestrator,
)
from app.storage.memory import MemoryProvider

from .conftest import sha, verifier

FILE = "file-0001"


def preferred(cluster, chunk_index, chunk_id=None):
    cid = chunk_id or f"chunk-{chunk_index}"
    return cluster.orch.placement.targets(FILE, cid, chunk_index, cluster.orch.provider_names,
                                          cluster.orch.replication_factor)


def chunk_with_target(cluster, provider, primary=False):
    for i in range(30):
        t = preferred(cluster, i)
        if (t[0] == provider) if primary else (provider in t[:cluster.orch.replication_factor]):
            return i, f"chunk-{i}"
    raise AssertionError("no chunk found")


def store(cluster, i, cid=None, data=None):
    cid = cid or f"chunk-{i}"
    data = data if data is not None else os.urandom(4096)
    return cluster.orch.store_chunk(FILE, cid, i, data, sha(data)), data


# --------------------------------------------------------------------------- store
def test_store_puts_exactly_r_replicas_on_distinct_providers(make_cluster):
    c = make_cluster()
    res, data = store(c, 0)
    assert len(res.stored_on) == 2 == len(set(res.stored_on))
    assert res.stored_on == preferred(c, 0)[:2]
    assert c.holders("chunk-0") == sorted(res.stored_on)
    assert res.failed == [] and res.degraded is False and res.failed_over is False
    for p in res.stored_on:
        assert c.mem[p].get("chunk-0") == data
    ev = c.audit.of("chunk.distribute")
    assert len(ev) == 1 and ev[0]["outcome"] == Outcome.SUCCESS
    assert ev[0]["details"] == {"chunk_index": 0, "providers": res.stored_on, "attempts": res.attempts,
                                "failed_providers": []}
    assert res.attempts == 6  # put + stat + read-back on two providers


def test_multi_chunk_file_spread_over_all_providers(make_cluster):
    c = make_cluster()
    per_provider = {n: 0 for n in c.mem}
    for i in range(9):
        res, _ = store(c, i)
        for p in res.stored_on:
            per_provider[p] += 1
    assert all(v == 6 for v in per_provider.values())  # 9 chunks * 2 replicas / 3 providers
    assert all(m.object_count() == 6 for m in c.mem.values())


def test_one_provider_unavailable_fails_over(make_cluster):
    c = make_cluster()
    i, cid = chunk_with_target(c, "p-b")
    c.faults["p-b"].set_mode("unavailable")
    res, _ = store(c, i, cid)
    assert "p-b" not in res.stored_on and len(res.stored_on) == 2
    assert res.failed_over is True and res.degraded is False
    assert [f.provider for f in res.failed] == ["p-b"]
    f = res.failed[0]
    assert f.error_type == "InjectedUnavailable" and f.injected and f.retryable and f.attempts == 3
    assert c.holders(cid) == sorted(res.stored_on)
    ev = c.audit.of("chunk.distribute")[-1]
    assert ev["outcome"] == Outcome.SUCCESS and ev["severity"] == Severity.WARNING
    assert ev["details"]["failed_providers"] == ["p-b"]


def test_degraded_when_fewer_than_r_but_at_least_min(make_cluster):
    c = make_cluster(r=3, min_write=2)
    c.faults["p-c"].set_mode("unavailable")
    res, _ = store(c, 0)
    assert len(res.stored_on) == 2 and res.degraded is True


def test_two_down_raises_and_leaves_nothing_behind(make_cluster):
    c = make_cluster(r=2, min_write=2)
    c.faults["p-a"].set_mode("unavailable")
    c.faults["p-b"].set_mode("unavailable")
    data = os.urandom(1000)
    with pytest.raises(ChunkStoreError) as ei:
        c.orch.store_chunk(FILE, "chunk-x", 0, data, sha(data))
    assert sorted(f.provider for f in ei.value.failures) == ["p-a", "p-b"]
    assert all(m.object_count() == 0 for m in c.mem.values())  # healthy p-c was cleaned up
    ev = c.audit.of("chunk.distribute")[-1]
    assert ev["outcome"] == Outcome.ERROR and ev["details"]["providers"] == []


def test_fail_n_retry_succeeds_and_metrics_count_retries(make_cluster):
    c = make_cluster(max_attempts=4)
    i, cid = chunk_with_target(c, "p-a")
    c.faults["p-a"].set_mode("fail-n", n=2)
    res, _ = store(c, i, cid)
    assert "p-a" in res.stored_on and res.failed == [] and res.failed_over is False
    assert c.metrics.get("p-a", "put", "retries") == 2
    assert c.metrics.get("p-a", "put", "attempts") == 3
    assert c.metrics.get("p-a", "put", "failures") == 2
    assert len(c.sleeps) == 2 and all(0 <= s <= 0.05 for s in c.sleeps)  # injected sleep, no waiting


def test_timeout_mode_handled(make_cluster):
    c = make_cluster()
    i, cid = chunk_with_target(c, "p-c")
    c.faults["p-c"].set_mode("timeout")
    res, _ = store(c, i, cid)
    assert "p-c" not in res.stored_on and len(res.stored_on) == 2
    assert res.failed[0].error_type == "InjectedTimeout"


def test_deadline_guard_turns_hung_provider_into_timeout(make_cluster):
    c = make_cluster(timeout=0.1, max_attempts=1)
    i, cid = chunk_with_target(c, "p-a")
    c.faults["p-a"].set_mode("slow", delay=0.4)   # real sleep inside the provider thread
    t0 = time.perf_counter()
    res, _ = store(c, i, cid)
    assert time.perf_counter() - t0 < 1.0
    assert "p-a" not in res.stored_on and len(res.stored_on) == 2
    assert res.failed[0].error_type == "ProviderTimeout"
    time.sleep(0.5)  # let the lingering provider thread finish (documented caveat)


def test_drop_writes_detected_by_verification(make_cluster):
    c = make_cluster()
    i, cid = chunk_with_target(c, "p-b")
    c.faults["p-b"].set_mode("drop-writes")
    res, _ = store(c, i, cid)
    assert "p-b" not in res.stored_on and len(res.stored_on) == 2
    f = res.failed[0]
    assert f.provider == "p-b" and f.error_type == "WriteVerificationError"
    assert "missing after acknowledged write" in f.message


def test_content_lying_provider_needs_readback_verification(make_cluster):
    # same size, wrong content on read: only the SHA-256 read-back catches it
    c = make_cluster(verify_writes=True)
    i, cid = chunk_with_target(c, "p-b")
    c.faults["p-b"].set_mode("corrupt-reads")
    res, _ = store(c, i, cid)
    assert "p-b" not in res.stored_on
    assert "hash mismatch" in res.failed[0].message

    c2 = make_cluster(verify_writes=False)
    c2.faults["p-b"].set_mode("corrupt-reads")
    res2, _ = store(c2, i, cid)
    assert "p-b" in res2.stored_on  # without read-back the lie is accepted (documented trade-off)
    assert c2.metrics.get("p-b", "get", "attempts") == 0


def test_store_rejects_bad_input(make_cluster):
    c = make_cluster()
    with pytest.raises(StorageError):
        c.orch.store_chunk(FILE, "c", 0, b"data", sha(b"other"))
    with pytest.raises(ValueError):
        c.orch.store_chunk(FILE, "c", 0, b"data", "nothex")
    with pytest.raises(InvalidObjectKey):
        c.orch.store_chunk(FILE, "anchors/evil", 0, b"data", sha(b"data"))
    with pytest.raises(InvalidObjectKey):
        c.orch.store_chunk(FILE, "../x", 0, b"data", sha(b"data"))
    assert all(m.object_count() == 0 for m in c.mem.values())


def test_audit_failure_on_success_rolls_back(make_cluster):
    c = make_cluster()
    c.audit.fail = True
    with pytest.raises(RuntimeError):
        store(c, 0)
    assert all(m.object_count() == 0 for m in c.mem.values())


def test_circuit_open_provider_is_skipped_without_requests(make_cluster):
    c = make_cluster(failure_threshold=2)
    c.health.record_failure("p-a", "down")
    c.health.record_failure("p-a", "down")
    assert c.health.breaker_state("p-a") == "open"
    i, cid = chunk_with_target(c, "p-a")
    res, _ = store(c, i, cid)
    assert "p-a" not in res.stored_on and res.failed[0].error_type == "CircuitOpenError"
    assert c.metrics.get("p-a", "put", "attempts") == 0
    c.clock.advance(31)  # cool-down over: half-open trial succeeds and closes the breaker
    res, _ = store(c, i, f"{cid}-again")
    assert "p-a" in res.stored_on and c.health.breaker_state("p-a") == "closed"


def test_passive_health_opens_breaker(make_cluster):
    c = make_cluster(failure_threshold=2, max_attempts=1)
    c.faults["p-a"].set_mode("unavailable")
    for i in range(6):
        store(c, i)
    assert c.health.breaker_state("p-a") == "open"
    row = {r["provider"]: r for r in c.orch.health_snapshot()}["p-a"]
    assert row["healthy"] is False and row["injected"] is True
    ev = [e for e in c.audit.of("storage.provider.health") if e["resource_id"] == "p-a"]
    assert ev[-1]["details"]["state"] == "open" and ev[-1]["outcome"] == Outcome.ERROR


# --------------------------------------------------------------------------- fetch
def test_fetch_normal(make_cluster):
    c = make_cluster()
    res, data = store(c, 0)
    out = c.orch.fetch_chunk("chunk-0", res.stored_on, verifier(data))
    assert out.data == data and out.provider == res.stored_on[0]
    assert [a.outcome for a in out.attempts] == ["ok"]
    assert c.audit.of("chunk.retrieve")[-1]["outcome"] == Outcome.SUCCESS


def test_fetch_primary_down_served_from_replica(make_cluster):
    c = make_cluster()
    res, data = store(c, 0)
    primary, replica = res.stored_on
    c.faults[primary].set_mode("unavailable")
    out = c.orch.fetch_chunk("chunk-0", res.stored_on, verifier(data))
    assert out.data == data and out.provider == replica
    assert [(a.provider, a.outcome) for a in out.attempts] == [(primary, "unavailable"), (replica, "ok")]
    assert out.attempts[0].retries == 2 and out.attempts[0].injected


def test_fetch_prefers_healthy_replicas(make_cluster):
    c = make_cluster()
    res, data = store(c, 0)
    primary, replica = res.stored_on
    c.health.record_failure(primary, "observed outage")
    out = c.orch.fetch_chunk("chunk-0", res.stored_on, verifier(data))
    assert [a.provider for a in out.attempts] == [replica]


def test_fetch_primary_corrupt_served_from_replica_and_audited(make_cluster):
    c = make_cluster()
    res, data = store(c, 0)
    primary, replica = res.stored_on
    c.faults[primary].set_mode("corrupt-reads")
    out = c.orch.fetch_chunk("chunk-0", res.stored_on, verifier(data))
    assert out.data == data and out.provider == replica
    assert [a.outcome for a in out.attempts] == ["corrupt", "ok"]
    ev = c.audit.of("storage.replica.corrupt")
    assert len(ev) == 1 and ev[0]["severity"] == Severity.CRITICAL
    assert ev[0]["details"] == {"provider": primary} and ev[0]["resource_id"] == "chunk-0"
    assert c.audit.of("chunk.retrieve")[-1]["severity"] == Severity.WARNING


def test_fetch_all_corrupt(make_cluster):
    c = make_cluster()
    res, data = store(c, 0)
    for p in res.stored_on:
        c.faults[p].set_mode("corrupt-reads")
    with pytest.raises(ChunkUnavailableError) as ei:
        c.orch.fetch_chunk("chunk-0", res.stored_on, verifier(data))
    assert ei.value.all_corrupt and ei.value.outcomes == ["corrupt", "corrupt"]
    ev = c.audit.of("chunk.retrieve")[-1]
    assert ev["outcome"] == Outcome.FAILURE and ev["severity"] == Severity.CRITICAL


def test_fetch_all_missing(make_cluster):
    c = make_cluster()
    with pytest.raises(ChunkUnavailableError) as ei:
        c.orch.fetch_chunk("nope", ["p-a", "p-b"], lambda d: True)
    assert ei.value.all_missing and not ei.value.any_corrupt
    assert len(c.audit.of("storage.replica.missing")) == 2
    assert c.audit.of("chunk.retrieve")[-1]["outcome"] == Outcome.ERROR


def test_fetch_mixed_missing_and_unavailable(make_cluster):
    c = make_cluster()
    c.faults["p-b"].set_mode("timeout")
    with pytest.raises(ChunkUnavailableError) as ei:
        c.orch.fetch_chunk("nope", ["p-a", "p-b", "unknown"], lambda d: True)
    assert sorted(ei.value.outcomes) == ["error", "missing", "timeout"]


def test_fetch_tries_open_breaker_as_last_resort(make_cluster):
    c = make_cluster(failure_threshold=1)
    res, data = store(c, 0)
    primary, replica = res.stored_on
    c.health.record_failure(primary, "down")         # open, but actually fine now
    c.faults[replica].set_mode("unavailable")
    out = c.orch.fetch_chunk("chunk-0", res.stored_on, verifier(data))
    assert out.provider == primary
    assert [a.provider for a in out.attempts] == [replica, primary]


# --------------------------------------------------------------------------- delete
def test_delete_is_tolerant(make_cluster):
    c = make_cluster()
    res, _ = store(c, 0)
    out = c.orch.delete_chunk("chunk-0", res.stored_on)
    assert sorted(out.deleted) == sorted(res.stored_on) and out.failed == []
    assert c.holders("chunk-0") == []
    out = c.orch.delete_chunk("chunk-0", res.stored_on)  # already gone: still fine
    assert out.failed == []


def test_delete_reports_unavailable_provider(make_cluster):
    c = make_cluster()
    res, _ = store(c, 0)
    c.faults[res.stored_on[0]].set_mode("unavailable")
    out = c.orch.delete_chunk("chunk-0", res.stored_on)
    assert out.deleted == [res.stored_on[1]]
    assert [f.provider for f in out.failed] == [res.stored_on[0]]


# --------------------------------------------------------------------------- scrub / repair
def test_verify_replica_states(make_cluster):
    c = make_cluster()
    res, data = store(c, 0)
    a, b = res.stored_on
    other = next(n for n in c.mem if n not in res.stored_on)
    h = sha(data)
    assert c.orch.verify_replica(a, "chunk-0", h) == "ok"
    assert c.orch.verify_replica(other, "chunk-0", h) == "missing"
    c.faults[b].set_mode("corrupt-reads")
    assert c.orch.verify_replica(b, "chunk-0", h) == "corrupt"
    c.faults[b].set_mode("unavailable")
    assert c.orch.verify_replica(b, "chunk-0", h) == "unavailable"


def test_repair_restores_r_replicas(make_cluster):
    c = make_cluster()
    res, data = store(c, 0)
    a, b = res.stored_on
    c.mem[b].put("chunk-0", b"\x00" * len(data))       # silently corrupted at rest
    assert c.orch.verify_replica(b, "chunk-0", sha(data)) == "corrupt"
    new = c.orch.repair_chunk("chunk-0", 0, FILE, data, sha(data), res.stored_on, [b])
    assert sorted(new) == sorted([a, b]) and c.mem[b].get("chunk-0") == data
    assert c.audit.of("chunk.repair")[-1]["outcome"] == Outcome.SUCCESS


def test_repair_uses_fallback_when_bad_provider_is_down(make_cluster):
    c = make_cluster()
    res, data = store(c, 0)
    a, b = res.stored_on
    c.mem[b].delete("chunk-0")
    c.faults[b].set_mode("unavailable")
    new = c.orch.repair_chunk("chunk-0", 0, FILE, data, sha(data), res.stored_on, [b])
    third = next(n for n in c.mem if n not in (a, b))
    assert new == [a, third] and c.mem[third].get("chunk-0") == data


def test_repair_refuses_bad_source_data(make_cluster):
    c = make_cluster()
    res, data = store(c, 0)
    with pytest.raises(StorageError):
        c.orch.repair_chunk("chunk-0", 0, FILE, b"garbage", sha(data), res.stored_on, [])


# --------------------------------------------------------------------------- anchors
def test_anchors_written_everywhere_and_listed(make_cluster):
    c = make_cluster()
    out = c.orch.put_anchor("checkpoint-000100.json", b'{"seq":100}')
    assert out.key == "anchors/checkpoint-000100.json"
    assert sorted(out.stored_on) == sorted(c.mem) and out.failed == []
    listing = c.orch.list_anchors()
    assert all(v == ["anchors/checkpoint-000100.json"] for v in listing.keys.values())
    reads = c.orch.get_anchor("anchors/checkpoint-000100.json")
    assert {r.outcome for r in reads.values()} == {"ok"} and reads["p-a"].data == b'{"seq":100}'


def test_anchors_best_effort_with_outage(make_cluster):
    c = make_cluster()
    c.faults["p-c"].set_mode("unavailable")
    out = c.orch.put_anchor("cp-1", b"x")
    assert sorted(out.stored_on) == ["p-a", "p-b"] and [f.provider for f in out.failed] == ["p-c"]
    listing = c.orch.list_anchors("cp-")
    assert "p-c" in listing.errors and listing.keys["p-a"] == ["anchors/cp-1"]
    assert c.orch.get_anchor("cp-1")["p-c"].outcome == "unavailable"
    with pytest.raises(InvalidObjectKey):
        c.orch.put_anchor("../../escape", b"x")


# --------------------------------------------------------------------------- misc
def test_concurrent_store_and_fetch(make_cluster):
    c = make_cluster()
    c.faults["p-c"].set_mode("fail-n", n=10)  # some retries under concurrency too
    errors = []

    def work(i):
        data = os.urandom(2048 + i)
        try:
            res = c.orch.store_chunk(f"file-{i}", f"cc-{i}", i, data, sha(data))
            out = c.orch.fetch_chunk(f"cc-{i}", res.stored_on, verifier(data))
            assert out.data == data and len(res.stored_on) == 2
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(repr(exc))

    with ThreadPoolExecutor(32) as pool:
        list(pool.map(work, range(64)))
    assert errors == []
    assert sum(m.object_count() for m in c.mem.values()) == 128
    assert len(c.audit.of("chunk.distribute")) == 64


def test_metrics_snapshot_after_operations(make_cluster):
    c = make_cluster()
    res, data = store(c, 0)
    c.orch.fetch_chunk("chunk-0", res.stored_on, verifier(data))
    snap = c.metrics.snapshot()
    p = res.stored_on[0]
    assert snap["counters"][p]["put"]["bytes"] == len(data)
    assert snap["counters"][p]["put"]["successes"] == 1
    assert snap["counters"][p]["get"]["successes"] == 2  # read-back + fetch
    assert "zt_storage_attempts_total" in c.metrics.render_prometheus()


def test_audit_events_contain_no_payload(make_cluster):
    c = make_cluster()
    data = b"SECRET-CIPHERTEXT-MARKER-" + os.urandom(64)
    res = c.orch.store_chunk(FILE, "chunk-p", 0, data, sha(data))
    c.faults[res.stored_on[0]].set_mode("corrupt-reads")
    c.orch.fetch_chunk("chunk-p", res.stored_on, verifier(data))
    c.orch.put_anchor("cp", data)
    text = repr(c.audit.events)
    assert "SECRET-CIPHERTEXT-MARKER" not in text and data.hex()[:32] not in text
    assert sha(data) not in text

    def no_bytes(v):
        if isinstance(v, (bytes, bytearray)):
            return False
        if isinstance(v, dict):
            return all(no_bytes(x) for x in v.values())
        if isinstance(v, (list, tuple)):
            return all(no_bytes(x) for x in v)
        return True
    assert all(no_bytes(e) for e in c.audit.events)


def test_set_fault_requires_fault_injection():
    mem = {n: MemoryProvider(n) for n in ("a", "b")}
    orch = StorageOrchestrator(mem, RotatingPlacement(), RetryPolicy(1, 0, 0), None, 2, 2)
    try:
        with pytest.raises(FaultInjectionDisabled):
            orch.set_fault("a", "unavailable")
        with pytest.raises(KeyError):
            orch.set_fault("zzz", "unavailable")
        assert orch.fault_status() == []
        rows = orch.health_snapshot()  # no monitor: probes directly
        assert [r["healthy"] for r in rows] == [True, True]
    finally:
        orch.close()


def test_set_fault_and_status(make_cluster):
    c = make_cluster()
    st = c.orch.set_fault("p-a", "fail-n", n=1)
    assert st["injected"] is True and st["remaining_failures"] == 1
    assert {s["provider"] for s in c.orch.fault_status()} == set(c.mem)


def test_constructor_validation():
    mem = {n: MemoryProvider(n) for n in ("a", "b")}
    with pytest.raises(ValueError):
        StorageOrchestrator(mem, RotatingPlacement(), RetryPolicy(), None, 3, 2)
    with pytest.raises(ValueError):
        StorageOrchestrator(mem, RotatingPlacement(), RetryPolicy(), None, 2, 3)
    with pytest.raises(ValueError):
        StorageOrchestrator({"x": MemoryProvider("y")}, RotatingPlacement(), RetryPolicy(), None, 1, 1)
