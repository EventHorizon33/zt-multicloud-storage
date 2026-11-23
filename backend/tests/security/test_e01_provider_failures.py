"""Part 2: provider failure scenarios against the REAL emulators (moto S3,
Azurite, gcp-storage-emulator) through the real boto3 / azure-storage-blob /
google-cloud-storage SDK adapters, with the whole application in front.

Each adapter is wrapped in ``FaultInjectingProvider`` so timeouts and
transient failures can be injected on top of the real SDK path; outages are
produced by killing an emulator PROCESS (``scripts/emulators.sh stop-one``).
Everything skips with a reason if an emulator is not reachable.

These prove behaviour against local emulators, not against AWS/Azure/GCP."""
from __future__ import annotations

import os
import socket
import subprocess
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

import pytest

from app.config import Settings
from app.storage import build_providers

from .conftest import MARKER, SecEnv, build_env, payload

pytestmark = [pytest.mark.emulator, pytest.mark.security]

REPO = Path(__file__).resolve().parents[3]
EMULATORS_SH = REPO / "scripts" / "emulators.sh"
S3_URL = os.environ.get("ZT_S3_ENDPOINT_URL", "http://127.0.0.1:5001")
GCS_URL = os.environ.get("ZT_GCS_ENDPOINT_URL", "http://127.0.0.1:9023")
AZURITE_CONN = os.environ.get(
    "ZT_AZURE_CONNECTION_STRING",
    # Azurite's public, documented development account (not a secret)
    "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;"
    "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
    "BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;")
# A bucket of our own (per test session), NOT the shared "zt-chunks". Since the F4 fix anchors are
# namespaced per audit log (anchors/audit/<log_id>/...), so sharing would no longer corrupt audit
# verification; the private bucket still keeps fault injection and cleanup away from other users.
BUCKET = "zt-sec-" + uuid.uuid4().hex[:10]
NAMES = ("aws-s3", "azure-blob", "gcs")


def _azure_url() -> str:
    for part in AZURITE_CONN.split(";"):
        if part.startswith("BlobEndpoint="):
            return part.split("=", 1)[1]
    return "http://127.0.0.1:10000"


def _reachable(url: str) -> bool:
    u = urlparse(url)
    try:
        with socket.create_connection((u.hostname, u.port or 80), timeout=1):
            return True
    except OSError:
        return False


def _script(*args) -> subprocess.CompletedProcess:
    return subprocess.run([str(EMULATORS_SH), *args], capture_output=True, text=True, timeout=120)


@pytest.fixture
def emu_env(tmp_path):
    for label, url in (("moto S3", S3_URL), ("Azurite blob", _azure_url()), ("gcp-storage-emulator", GCS_URL)):
        if not _reachable(url):
            pytest.skip(f"{label} emulator not reachable at {url} (run scripts/emulators.sh start)")
    overrides = dict(storage_providers=",".join(NAMES), s3_endpoint_url=S3_URL, s3_bucket=BUCKET,
                     s3_access_key_id="test", s3_secret_access_key="test", azure_connection_string=AZURITE_CONN,
                     azure_container=BUCKET, gcs_endpoint_url=GCS_URL, gcs_bucket=BUCKET, gcs_project="zt-local",
                     chunk_size_bytes=4096, enable_fault_injection=True, storage_timeout_seconds=3.0,
                     rate_limit_login_per_minute=10_000, rate_limit_register_per_minute=10_000)
    settings = Settings(_env_file=None, env="test", data_dir=tmp_path, **overrides)
    providers = build_providers(settings, enable_fault_injection=True)
    for p in providers.values():
        p.inner.ensure_bucket()
        st = p.health()
        if not st.healthy:
            pytest.skip(f"{p.name} emulator unhealthy: {st.error}")
    env, client = build_env(tmp_path / "app", providers=providers, **overrides)
    client.__enter__()
    senv = SecEnv(**{k: getattr(env, k) for k in type(env).__dataclass_fields__})
    yield senv
    client.__exit__(None, None, None)
    for p in providers.values():                   # the bucket is ours: remove every object (chunks + anchors)
        try:
            for key in list(p.inner.list_keys("")):
                p.inner.delete(key)
        except Exception:
            pass


def _sdk(env, name):
    """The raw SDK adapter (no fault injection), i.e. direct access to the emulator."""
    return env.providers[name].inner


def _upload(env, token, data, **kw):
    return env.upload_ok(token, data, **kw)


def _health(env, name):
    return next(r for r in env.client.get("/api/storage/providers",
                                          headers=env.h(env.login("ops-viewer"))).json()["providers"]
                if r["provider"] == name)


def _wait_healthy(env, name, seconds=30):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if env.providers[name].inner.health().healthy:
            break
        time.sleep(0.3)
    rows = {r["provider"]: r for r in env.container.health.check_all()}
    return rows[name]


def _stop(name, url):
    out = _script("stop-one", name)
    assert out.returncode == 0, out.stderr
    deadline = time.time() + 15
    while _reachable(url) and time.time() < deadline:
        time.sleep(0.2)
    assert not _reachable(url), f"{name} emulator still answering after stop-one: {out.stdout}"


def _start(name):
    out = _script("start-one", name)
    assert out.returncode == 0, out.stderr + out.stdout


def _need_managed(name):
    if f"[{name}] running" not in _script("status").stdout:
        pytest.skip(f"{name} emulator is not managed by scripts/emulators.sh; cannot stop it")


def test_e01_provider_unavailable_reads_fail_over_writes_go_elsewhere(emu_env, evidence):
    env = emu_env
    ev = evidence("E01", "Kill the gcp-storage-emulator process (real outage)",
                  "Replica failover on read, placement failover on write, health monitor + breaker")
    _need_managed("gcs")
    env.register("ops-viewer")
    alice = env.user("alice")
    data = payload(5)
    meta = _upload(env, alice, data)
    on_gcs = [c for c in env.chunk_rows(meta["id"]) if "gcs" in c[2]]
    assert on_gcs
    _stop("gcs", GCS_URL)
    try:
        rows = {r["provider"]: r for r in env.container.health.check_all()}
        assert rows["gcs"]["healthy"] is False and rows["gcs"]["injected"] is False
        assert _health(env, "gcs")["healthy"] is False
        h = [e for e in env.audit_events(event_type="storage.provider.health", resource_id="gcs")
             if e["outcome"] == "error"]
        assert h and h[-1]["details"]["healthy"] is False and h[-1]["details"]["injected"] is False
        r = env.req("GET", f"/api/files/{meta['id']}/download", alice)
        assert r.status_code == 200 and r.content == data                      # reads fail over
        new = _upload(env, alice, payload(4))
        reps = {p for _, _, rs in env.chunk_rows(new["id"]) for p in rs}
        assert reps == {"aws-s3", "azure-blob"}                                 # writes go elsewhere
        dist = env.audit_events(event_type="chunk.distribute")
        assert dist and all("gcs" not in (e["details"].get("providers") or []) for e in dist[-4:])
        ev.result(f"health gcs healthy=false injected=false; download 200 byte-identical; "
                  f"new upload replicas on {sorted(reps)}")
        ev.audit(h[-1])
    finally:
        _start("gcs")
    row = _wait_healthy(env, "gcs")
    assert row["healthy"] is True and row["state"] == "closed"
    up = [e for e in env.audit_events(event_type="storage.provider.health", resource_id="gcs")
          if e["outcome"] == "success"]
    assert up and up[-1]["details"]["healthy"] is True
    assert env.download(alice, meta["id"]).content == data


def test_e02_object_missing_at_one_provider_served_from_replica(emu_env, evidence):
    env = emu_env
    ev = evidence("E02", "Delete every Azure copy of a file's chunks via the Azure SDK",
                  "ObjectNotFound -> next replica; replica marked missing")
    alice = env.user("alice")
    data = payload(4)
    meta = _upload(env, alice, data)
    victims = [cid for cid, _, reps in env.chunk_rows(meta["id"]) if "azure-blob" in reps]
    for cid in victims:                    # every Azure copy of this file (some are the first replica tried)
        _sdk(env, "azure-blob").delete(cid)
    r = env.req("GET", f"/api/files/{meta['id']}/download", alice)
    assert r.status_code == 200 and r.content == data
    miss = env.audit_events(event_type="storage.replica.missing")
    assert miss and all(e["severity"] == "warning" and e["details"]["provider"] == "azure-blob" for e in miss)
    assert {e["resource_id"] for e in miss} <= set(victims)
    v = env.req("POST", f"/api/files/{meta['id']}/verify", alice).json()
    assert v["summary"]["missing"] == len(victims) and v["recoverable"] is True
    ev.response(r)
    ev.audit(miss[-1])


def test_e03_corrupted_object_detected_and_replica_used(emu_env, evidence):
    env = emu_env
    ev = evidence("E03", "Overwrite every S3 copy of a file's chunks via boto3 with same-size garbage",
                  "SHA-256 mismatch -> corrupt replica skipped; critical audit")
    alice = env.user("alice")
    data = payload(4)
    meta = _upload(env, alice, data)
    victims = {cid: idx for cid, idx, reps in env.chunk_rows(meta["id"]) if "aws-s3" in reps}
    s3 = _sdk(env, "aws-s3")
    for cid in victims:
        s3.put(cid, os.urandom(len(s3.get(cid))))
    r = env.req("GET", f"/api/files/{meta['id']}/download", alice)
    assert r.status_code == 200 and r.content == data
    bad = env.audit_events(event_type="storage.replica.corrupt")
    assert bad and all(e["severity"] == "critical" and e["details"]["provider"] == "aws-s3" for e in bad)
    v = env.req("POST", f"/api/files/{meta['id']}/verify", alice).json()
    assert v["summary"]["corrupt"] == len(victims)
    rp = env.req("POST", f"/api/files/{meta['id']}/repair", alice).json()
    assert rp["ok"] and sorted(rp["repaired_chunks"]) == sorted(victims.values())
    assert env.req("POST", f"/api/files/{meta['id']}/verify", alice).json()["healthy"] is True
    ev.response(r)
    ev.audit(bad[-1])


def test_e04_timeout_is_retried_then_fails_over(emu_env, evidence):
    env = emu_env
    ev = evidence("E04", "Every call to Azure times out (fault mode 'timeout' over the real SDK adapter)",
                  "Bounded retries with backoff, then replica failover; injected flag kept")
    alice = env.user("alice")
    data = payload(4)
    meta = _upload(env, alice, data)
    m = env.container.orchestrator.metrics
    retries_before = m.get("azure-blob", "get", "retries")
    env.fault("azure-blob", "timeout", delay=0)
    try:
        r = env.req("GET", f"/api/files/{meta['id']}/download", alice)
        assert r.status_code == 200 and r.content == data
        assert m.get("azure-blob", "get", "retries") > retries_before
        ret = env.audit_events(event_type="chunk.retrieve")
        outcomes = [e["details"].get("outcomes") for e in ret[-6:]]
        assert any("timeout" in str(o) for o in outcomes), outcomes
    finally:
        env.fault("azure-blob", "none")
    ev.result(f"200 byte-identical; azure-blob get retries +{m.get('azure-blob', 'get', 'retries') - retries_before}")
    ev.audit(next(e for e in reversed(ret) if "timeout" in str(e["details"].get("outcomes"))))


def test_e05_transient_failures_retry_succeeds(emu_env, evidence):
    env = emu_env
    ev = evidence("E05", "GCS fails the next 2 calls (fault mode fail-n) during upload",
                  "RetryPolicy (max 4 attempts) succeeds on the same provider; no failover needed")
    alice = env.user("alice")
    m = env.container.orchestrator.metrics
    before = m.get("gcs", "put", "retries")
    env.fault("gcs", "fail-n", n=2)
    data = payload(4)
    meta = _upload(env, alice, data)
    status = next(f for f in env.client.get("/api/storage/faults", headers=env.h(env.admin()[0])).json()["faults"]
                  if f["provider"] == "gcs")
    env.fault("gcs", "none")
    assert status["remaining_failures"] == 0 and status["injected_failures_total"] >= 2
    assert m.get("gcs", "put", "retries") - before >= 1
    assert any("gcs" in reps for _, _, reps in env.chunk_rows(meta["id"]))     # gcs still got its replicas
    assert env.download(alice, meta["id"]).content == data
    dist = [e for e in env.audit_events(event_type="chunk.distribute") if "gcs" in (e["details"].get("providers") or [])]
    assert dist and dist[0]["outcome"] == "success"
    ev.result(f"upload 201; gcs put retries +{m.get('gcs', 'put', 'retries') - before}; replicas still on gcs")
    ev.audit(dist[0])


def test_e06_chunk_permanently_unavailable_is_503(emu_env, evidence):
    env = emu_env
    ev = evidence("E06", "Delete one chunk at EVERY provider holding it (via each SDK)",
                  "No reconstruction beyond R; 503 data-unavailable, no partial content")
    alice = env.user("alice")
    data = payload(4)
    meta = _upload(env, alice, data)
    cid, idx, reps = env.chunk_rows(meta["id"])[1]
    for p in reps:
        _sdk(env, p).delete(cid)
    r = env.req("GET", f"/api/files/{meta['id']}/download", alice)
    assert r.status_code == 503 and r.json()["error"] == "data-unavailable"
    assert MARKER not in r.content
    dl = env.one(r, "file.download")
    assert (dl["outcome"], dl["reason"]) == ("error", "data-unavailable")
    assert len(env.audit_events(event_type="storage.replica.missing", resource_id=cid)) == 2
    rp = env.req("POST", f"/api/files/{meta['id']}/repair", alice).json()
    assert rp["ok"] is False and rp["unrepairable_chunks"] == [idx]
    ev.response(r)
    ev.audit(dl)


def test_e07_repair_restores_replication_after_provider_returns(emu_env, evidence):
    env = emu_env
    ev = evidence("E07", "GCS down AND the other replica of some chunks lost; GCS comes back",
                  "Outage -> 503 + unrepairable; provider returns -> repair copies from it, verify healthy")
    _need_managed("gcs")
    alice = env.user("alice")
    data = payload(6)
    meta = _upload(env, alice, data)
    pairs = [(cid, idx, reps) for cid, idx, reps in env.chunk_rows(meta["id"]) if "gcs" in reps]
    assert pairs
    _stop("gcs", GCS_URL)
    try:
        env.container.health.check_all()
        for cid, _, reps in pairs:                                  # lose the non-gcs replica of those chunks
            other = next(p for p in reps if p != "gcs")
            _sdk(env, other).delete(cid)
        r = env.req("GET", f"/api/files/{meta['id']}/download", alice)
        assert r.status_code == 503
        v = env.req("POST", f"/api/files/{meta['id']}/verify", alice).json()
        assert v["recoverable"] is False and v["summary"]["unavailable"] >= len(pairs)
        rp = env.req("POST", f"/api/files/{meta['id']}/repair", alice).json()
        assert rp["ok"] is False
    finally:
        _start("gcs")
    assert _wait_healthy(env, "gcs")["healthy"] is True
    rp = env.req("POST", f"/api/files/{meta['id']}/repair", alice)
    assert rp.status_code == 200 and rp.json()["ok"] is True
    assert sorted(rp.json()["repaired_chunks"]) == sorted(i for _, i, _ in pairs)
    v = env.req("POST", f"/api/files/{meta['id']}/verify", alice).json()
    assert v["healthy"] is True
    r = env.req("GET", f"/api/files/{meta['id']}/download", alice)
    assert r.status_code == 200 and r.content == data
    rep_ev = env.audit_events(event_type="file.repair", resource_id=meta["id"])
    assert [e["outcome"] for e in rep_ev][-2:] == ["failure", "success"]
    assert env.audit_events(event_type="chunk.repair")
    ev.result(f"during outage: 503, repair ok=false; after return: repaired {len(pairs)} chunk(s), verify healthy, 200")
    ev.audit(rep_ev[-1])

