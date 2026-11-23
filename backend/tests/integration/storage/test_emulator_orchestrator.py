"""Orchestrator over the three real SDK adapters + emulators, including a
real outage produced by killing one emulator process."""
from __future__ import annotations

import hashlib
import os
import subprocess
import time
import uuid

import pytest

from app.storage import HealthMonitor, RetryPolicy, RotatingPlacement, StorageMetrics, StorageOrchestrator

from .conftest import EMULATORS_SH, GCS_URL, _reachable, make_gcs

pytestmark = pytest.mark.emulator


class Audit:
    def __init__(self):
        self.events = []

    def record(self, **kw):
        self.events.append(kw)


@pytest.fixture
def orch(all_providers):
    audit = Audit()
    health = HealthMonitor(all_providers, interval=60, failure_threshold=3, cooldown_seconds=30, audit=audit)
    o = StorageOrchestrator(all_providers, RotatingPlacement(), RetryPolicy(2, 0.01, 0.05), health,
                            replication_factor=2, min_write_replicas=2, audit=audit, timeout_seconds=8,
                            metrics=StorageMetrics())
    o.audit_events = audit.events
    yield o
    o.close()


def _chunks(n):
    file_id = f"file-{uuid.uuid4().hex}"
    prefix = f"it-{uuid.uuid4().hex[:12]}/"
    out = []
    for i in range(n):
        data = os.urandom(32 * 1024 + i)
        out.append((file_id, f"{prefix}chunk-{i:03d}", i, data, hashlib.sha256(data).hexdigest()))
    return prefix, out


def test_ten_chunks_physically_spread_across_three_emulators(orch, all_providers):
    prefix, chunks = _chunks(10)
    results = {}
    for file_id, cid, i, data, sha in chunks:
        res = orch.store_chunk(file_id, cid, i, data, sha)
        assert len(res.stored_on) == 2 and not res.degraded and res.failed == []
        results[cid] = res.stored_on

    # ground truth from each SDK adapter, not from the orchestrator's report
    listed = {name: sorted(p.list_keys(prefix)) for name, p in all_providers.items()}
    assert all(len(keys) > 0 for keys in listed.values()), listed
    assert sum(len(k) for k in listed.values()) == 20
    for cid, stored_on in results.items():
        assert sorted(n for n, keys in listed.items() if cid in keys) == sorted(stored_on)
    # rotating placement over 10 chunks: 6/7/7 split
    assert sorted(len(k) for k in listed.values()) == [6, 7, 7]

    for file_id, cid, i, data, sha in chunks:
        out = orch.fetch_chunk(cid, results[cid], lambda b, s=sha: hashlib.sha256(b).hexdigest() == s)
        assert out.data == data

    for cid, stored_on in results.items():
        assert orch.delete_chunk(cid, stored_on).failed == []
    assert all(list(p.list_keys(prefix)) == [] for p in all_providers.values())


def test_anchor_on_all_three_emulators(orch, all_providers):
    key = f"it-{uuid.uuid4().hex[:8]}.json"
    res = orch.put_anchor(key, b'{"seq": 1}')
    assert sorted(res.stored_on) == sorted(all_providers)
    reads = orch.get_anchor(key)
    assert all(r.outcome == "ok" and r.data == b'{"seq": 1}' for r in reads.values())
    for p in all_providers.values():
        p.delete(res.key)


def _script(*args):
    return subprocess.run([str(EMULATORS_SH), *args], capture_output=True, text=True, timeout=120)


def test_real_outage_by_stopping_gcs_emulator(orch, all_providers):
    status = _script("status").stdout
    if "[gcs] running" not in status:
        pytest.skip("gcs emulator is not managed by scripts/emulators.sh; cannot stop it for the outage test")
    prefix, chunks = _chunks(6)
    stored = {}
    for file_id, cid, i, data, sha in chunks:
        stored[cid] = orch.store_chunk(file_id, cid, i, data, sha).stored_on
    on_gcs = [c for c in chunks if "gcs" in stored[c[1]]]
    assert on_gcs, "rotating placement must put some replicas on gcs"

    out = _script("stop-one", "gcs")
    assert out.returncode == 0, out.stderr
    try:
        assert not _reachable(GCS_URL)
        # health reports it down (active probe on the real adapter)
        rows = {r["provider"]: r for r in orch.health.check_all()}
        assert rows["gcs"]["healthy"] is False and rows["gcs"]["injected"] is False
        assert "connection failed" in rows["gcs"]["last_error"]
        assert rows["aws-s3"]["healthy"] and rows["azure-blob"]["healthy"]

        for file_id, cid, i, data, sha in on_gcs:
            res = orch.fetch_chunk(cid, stored[cid], lambda b, s=sha: hashlib.sha256(b).hexdigest() == s)
            assert res.data == data and res.provider != "gcs"
            # gcs is unhealthy now, so it is ordered last and never needed
            assert all(a.provider != "gcs" for a in res.attempts)
        # forcing gcs first shows a real connection failure, then failover
        file_id, cid, i, data, sha = on_gcs[0]
        orch.health.record_success("gcs")  # pretend we have not noticed yet
        res = orch.fetch_chunk(cid, ["gcs"] + [p for p in stored[cid] if p != "gcs"],
                               lambda b, s=sha: hashlib.sha256(b).hexdigest() == s)
        assert [a.outcome for a in res.attempts] == ["unavailable", "ok"]

        # new writes whose preferred targets include gcs fail over to the third provider
        file_id2 = f"file-{uuid.uuid4().hex}"
        for i in range(3):
            data = os.urandom(1000)
            r = orch.store_chunk(file_id2, f"{prefix}new-{i}", i, data, hashlib.sha256(data).hexdigest())
            assert "gcs" not in r.stored_on and len(r.stored_on) == 2
        down_events = [e for e in orch.audit_events
                       if e["event_type"] == "storage.provider.health" and e["resource_id"] == "gcs"]
        assert any(e["outcome"].value == "error" for e in down_events)
    finally:
        out = _script("start-one", "gcs")
        assert out.returncode == 0, out.stderr + out.stdout

    deadline = time.time() + 20
    while time.time() < deadline and not make_gcs().health().healthy:
        time.sleep(0.2)
    rows = {r["provider"]: r for r in orch.health.check_all()}
    assert rows["gcs"]["healthy"] is True and rows["gcs"]["state"] == "closed"
    # data written before the outage survived the restart (on-disk emulator storage)
    file_id, cid, i, data, sha = on_gcs[0]
    assert all_providers["gcs"].get(cid) == data
    for p in all_providers.values():
        for k in list(p.list_keys(prefix)):
            p.delete(k)
