"""Logic of the benchmark and real-cloud tooling in scripts/bench/.

No cloud, no emulator and no server is started here: provider calls are replaced with in-memory
providers and stubs. What is checked is the part that protects money and data (volume model, byte
budget, bucket-name and credential checks, cleanup, failure handling) and the statistics helpers.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import pytest

from app.storage.memory import MemoryProvider

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO / "scripts" / "bench"))

import bench  # noqa: E402
import breakdown  # noqa: E402
import limits  # noqa: E402
import realcloud  # noqa: E402

MIB, GIB = 1024 * 1024, 1024 ** 3
REAL_ENV = ["ZT_S3_BUCKET", "ZT_S3_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE", "ZT_S3_ACCESS_KEY_ID",
            "ZT_S3_SECRET_ACCESS_KEY", "ZT_AZURE_CONNECTION_STRING", "ZT_AZURE_CONTAINER", "ZT_GCS_BUCKET",
            "GOOGLE_APPLICATION_CREDENTIALS", "ZT_S3_ENDPOINT_URL", "ZT_GCS_ENDPOINT_URL"]


@pytest.fixture
def clean_env(monkeypatch):
    for k in REAL_ENV:
        monkeypatch.delenv(k, raising=False)
    return monkeypatch


def full_real_env(monkeypatch, tmp_path, *, bench_names=True):
    key = tmp_path / "key.json"
    key.write_text("{}")
    suffix = "-bench" if bench_names else ""
    monkeypatch.setenv("ZT_S3_BUCKET", f"zt{suffix}-s3")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAFAKEFORTEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "fake-secret-for-test")
    monkeypatch.setenv("ZT_AZURE_CONNECTION_STRING", "DefaultEndpointsProtocol=https;AccountName=fake;AccountKey=ZmFrZQ==;")
    monkeypatch.setenv("ZT_AZURE_CONTAINER", f"zt{suffix}-az")
    monkeypatch.setenv("ZT_GCS_BUCKET", f"zt{suffix}-gcs")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(key))


# ----------------------------- volume model and plan ------------------------------------------ #
def test_backend_volumes_for_a_100_mib_file_in_16_mib_chunks():
    v = realcloud.volumes("backend", 100 * MIB, 16 * MIB)             # 7 chunks, each written to 2 providers
    assert v == dict(ingress=200 * MIB, egress=300 * MIB, put=14, get=21, delete=14)


def test_direct_volumes_are_one_object_one_provider():
    assert realcloud.volumes("direct", 40 * MIB) == dict(ingress=40 * MIB, egress=40 * MIB, put=1, get=1, delete=1)


def test_default_plan_totals_match_the_documented_full_plan():
    a = argparse.Namespace(sizes_mib="10,40,100,1024", chunks_mib="1,16", repeats=5, repeats_large=3, baseline_max_mib=1024)
    t = realcloud.build_plan(a)["total"]
    assert t["measurements"] == 90
    assert round(t["ingress"] / GIB, 1) == 26.1 and round(t["egress"] / GIB, 1) == 33.6
    assert (t["put"], t["get"], t["delete"]) == (8192, 12261, 8192)


def test_plan_tells_the_cap_rounded_up_never_down(capsys):
    a = argparse.Namespace(sizes_mib="10,40,100", chunks_mib="16", repeats=5, repeats_large=3, baseline_max_mib=100,
                           price_egress_gib=0, price_ingress_gib=0, price_per_1000_requests=0)
    realcloud.cmd_plan(a)
    out = capsys.readouterr().out
    t = realcloud.build_plan(a)["total"]
    need = (t["ingress"] + t["egress"]) / GIB
    assert f"must be at least {int(need) + 1} for this plan" in out        # 8.1 GiB needs a cap of 9, not 8


def test_budget_stops_before_the_cap_is_exceeded_and_never_for_no_cap():
    b = realcloud.Budget(0.001)                                          # about 1 MiB
    with pytest.raises(SystemExit, match="Budget cap reached"):
        b.charge(realcloud.volumes("direct", 2 * MIB))
    free = realcloud.Budget(None)
    free.charge(realcloud.volumes("direct", 50 * GIB))                   # no cap: never raises
    assert free.moved == 100 * GIB


# ----------------------------- credentials and safety rules ----------------------------------- #
def test_nothing_configured_lists_every_missing_item_without_values(clean_env):
    missing = realcloud.missing_real_env()
    joined = " | ".join(missing)
    for needle in ("ZT_S3_BUCKET", "AWS credentials", "ZT_AZURE_CONNECTION_STRING", "ZT_AZURE_CONTAINER", "ZT_GCS_BUCKET",
                   "GOOGLE_APPLICATION_CREDENTIALS"):
        assert needle in joined


def test_a_complete_real_configuration_has_nothing_missing(clean_env, tmp_path):
    full_real_env(clean_env, tmp_path)
    assert realcloud.missing_real_env() == []


@pytest.mark.parametrize("var,value,fragment", [
    ("ZT_S3_ENDPOINT_URL", "http://127.0.0.1:5001", "must be UNSET"),
    ("ZT_GCS_ENDPOINT_URL", "http://127.0.0.1:9023", "must be UNSET"),
    ("ZT_AZURE_CONNECTION_STRING", "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=x;", "Azurite"),
])
def test_emulator_settings_are_refused_for_a_real_run(clean_env, tmp_path, var, value, fragment):
    full_real_env(clean_env, tmp_path)
    clean_env.setenv(var, value)
    assert any(fragment in m for m in realcloud.missing_real_env())


def test_a_real_run_refuses_bucket_names_without_bench(clean_env, tmp_path):
    full_real_env(clean_env, tmp_path, bench_names=False)
    with pytest.raises(SystemExit, match="bench"):
        realcloud.open_target(argparse.Namespace(target="real", allow_any_bucket_name=False))


def test_a_real_run_accepts_dedicated_bench_buckets_without_contacting_anything(clean_env, tmp_path):
    full_real_env(clean_env, tmp_path)
    env, teardown = realcloud.open_target(argparse.Namespace(target="real", allow_any_bucket_name=False))
    assert env == {}
    teardown()


def test_cleanup_needs_the_exact_bucket_names_typed_back(clean_env, tmp_path):
    full_real_env(clean_env, tmp_path)
    with pytest.raises(SystemExit, match="zt-bench-s3,zt-bench-az,zt-bench-gcs"):
        realcloud.cmd_cleanup(argparse.Namespace(target="real", allow_any_bucket_name=False, yes_empty_buckets="yes"))


def test_a_real_run_without_a_byte_cap_is_refused(clean_env, tmp_path):
    full_real_env(clean_env, tmp_path)
    a = argparse.Namespace(target="real", allow_any_bucket_name=False, sizes_mib="10", chunks_mib="16", repeats=1,
                           repeats_large=1, baseline_max_mib=10, max_transfer_gib=0, host_label="", out=str(tmp_path / "o"))
    with pytest.raises(SystemExit, match="max-transfer-gib"):
        realcloud.cmd_run(a)


# ----------------------------- the run loop: cleanup and failure handling --------------------- #
def _run_args(out, **kw):
    base = dict(target="emulators", allow_any_bucket_name=False, sizes_mib="1", chunks_mib="16", repeats=3, repeats_large=3,
                baseline_max_mib=1, max_transfer_gib=1.0, host_label="unit test", out=str(out))
    base.update(kw)
    return argparse.Namespace(**base)


def _stub_run(monkeypatch, backend):
    monkeypatch.setattr(realcloud, "open_target", lambda a: ({}, lambda: None))
    monkeypatch.setattr(realcloud, "make_providers", lambda timeout: {n: MemoryProvider(n) for n in realcloud.PROVS})
    monkeypatch.setattr(realcloud, "measure_backend", backend)


def test_failed_measurements_are_recorded_and_the_run_continues(monkeypatch, tmp_path, capsys):
    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise TimeoutError("simulated provider timeout")
        return dict(upload_s=0.1, download_s=0.05, ttfb_s=0.01, verified=True, server_peak_rss_mib=100)

    _stub_run(monkeypatch, flaky)
    out = tmp_path / "run"
    realcloud.cmd_run(_run_args(out))
    rows = [json.loads(l) for l in (out / "measurements.jsonl").read_text().splitlines()]
    failed = [r for r in rows if r.get("failed")]
    assert len(rows) == 12 and len(failed) == 2
    assert all("TimeoutError" in r["error"] and r["verified"] is False for r in failed)
    realcloud.cmd_summarize(argparse.Namespace(dir=str(out)))
    assert "10 completed, 2 failed" in capsys.readouterr().out


def test_three_failures_in_a_row_stop_the_run(monkeypatch, tmp_path):
    def always(*a, **k):
        raise TimeoutError("simulated outage")

    _stub_run(monkeypatch, always)
    monkeypatch.setattr(realcloud, "measure_direct", always)
    out = tmp_path / "run"
    with pytest.raises(SystemExit, match="3 measurements failed in a row"):
        realcloud.cmd_run(_run_args(out))
    assert len((out / "measurements.jsonl").read_text().splitlines()) == 3


def test_leftover_objects_are_deleted_after_every_measurement(monkeypatch, tmp_path):
    shared = {n: MemoryProvider(n) for n in realcloud.PROVS}

    def leaves_objects(*a, **k):
        shared["aws-s3"].put("chunk-1", b"x")
        shared["gcs"].put("chunk-2", b"y")
        return dict(upload_s=0.1, download_s=0.05, ttfb_s=0.01, verified=True, server_peak_rss_mib=1)

    monkeypatch.setattr(realcloud, "open_target", lambda a: ({}, lambda: None))
    monkeypatch.setattr(realcloud, "make_providers", lambda timeout: shared)
    monkeypatch.setattr(realcloud, "measure_backend", leaves_objects)
    out = tmp_path / "run"
    realcloud.cmd_run(_run_args(out, repeats=1, repeats_large=1))
    backend_rows = [json.loads(l) for l in (out / "measurements.jsonl").read_text().splitlines() if '"kind": "backend"' in l]
    assert backend_rows[0]["objects_removed"] == 2
    assert all(not list(p.list_keys("")) for p in shared.values())


# ----------------------------- emulator start-up retry ---------------------------------------- #
def test_emulator_start_retries_and_then_succeeds(monkeypatch):
    calls = []

    def flaky_once(self):
        calls.append(1)
        if len(calls) < 3:
            raise RuntimeError("bucket setup failed: 501")
        return {"ZT_S3_ENDPOINT_URL": "http://127.0.0.1:1"}

    monkeypatch.setattr(bench.ManagedEmulators, "_start_once", flaky_once)
    monkeypatch.setattr(bench.time, "sleep", lambda s: None)
    env = bench.ManagedEmulators().start()
    assert len(calls) == 3 and "ZT_S3_ENDPOINT_URL" in env


def test_emulator_start_gives_up_after_three_attempts_and_stop_is_safe(monkeypatch):
    def broken(self):
        raise RuntimeError("never ready")

    monkeypatch.setattr(bench.ManagedEmulators, "_start_once", broken)
    monkeypatch.setattr(bench.time, "sleep", lambda s: None)
    emu = bench.ManagedEmulators()
    with pytest.raises(RuntimeError, match="did not start after 3 attempts"):
        emu.start()
    emu.stop()                                                           # must not raise after a failed start


# ----------------------------- statistics helpers --------------------------------------------- #
def test_bootstrap_interval_is_deterministic_and_brackets_the_median():
    xs = [float(i) for i in range(1, 11)]
    lo, hi = breakdown.boot_ci(xs)
    assert (lo, hi) == breakdown.boot_ci(xs)
    assert lo <= 5.5 <= hi and 1.0 <= lo and hi <= 10.0


def test_bootstrap_interval_of_degenerate_samples():
    assert breakdown.boot_ci([3.0]) == (3.0, 3.0)
    assert breakdown.boot_ci([2.0] * 8) == (2.0, 2.0)


def test_summarize_reports_the_usual_figures():
    s = bench.summarize([1.0, 2.0, 3.0, 4.0, 5.0])
    assert (s["n"], s["min"], s["median"], s["max"], s["mean"]) == (5, 1.0, 3.0, 5.0, 3.0)
    assert s["stdev"] == pytest.approx(1.5811, abs=1e-3) and s["p95"] == 5.0


def test_throttled_file_limits_the_rate_and_exposes_a_descriptor(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(os.urandom(64 * 1024))
    f = limits.ThrottledFile(p, rate=128 * 1024)                          # 64 KiB at 128 KiB/s takes about half a second
    assert os.fstat(f.fileno()).st_size == 64 * 1024
    t0 = time.perf_counter()
    got = b""
    while chunk := f.read(16 * 1024):
        got += chunk
    elapsed = time.perf_counter() - t0
    f.close()
    assert got == p.read_bytes() and 0.35 <= elapsed <= 3.0
