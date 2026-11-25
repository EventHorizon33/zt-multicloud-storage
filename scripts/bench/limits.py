#!/usr/bin/env python3
"""Phase 2: what limits large files, and what happens at multi-GiB sizes.

  defaults   Confirms by experiment what the code suggests, with SHIPPED settings for the caps and
             the bulk-download detector (only what the test needs is overridden):
               E1  a 300 MiB upload against the default 256 MiB cap
               E2  upload cap raised only (600 MiB upload works), detector at its default:
                   is the 600 MiB download refused, is the user blocked, what is audited?
               E3  same as E2 with the detector's byte threshold raised (control)
  big        Multi-GiB upload and download with TEST-ONLY settings (cap raised, detector raised),
             16 MiB chunks and a 30 s provider deadline (the deployment values), over the two
             disk-backed emulators (Azurite, GCS) so that memory is not the limit. Records time,
             time to first byte, server peak memory, disk growth and a byte check. Also a slow
             upload that outlives the 5-minute access token.

Nothing here changes a shipped default. Run from the backend directory with the project venv:

  .venv/bin/python ../scripts/bench/limits.py defaults
  .venv/bin/python ../scripts/bench/limits.py big --sizes-gib 2,5,10 --slow-gib 3 --slow-mib-s 8

Safety: a monitor samples available memory every 2 s and kills the server if it falls below 2 GiB.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import bench  # noqa: E402

MIB = bench.MIB
GIB = 1024 * MIB
MEM_FLOOR_MIB = 2000


# --------------------------------------------------------------------------- #
# internal server with explicit, minimal overrides
# --------------------------------------------------------------------------- #
def cmd_serve(a) -> None:
    import uvicorn

    from app.config import Settings
    from app.main import create_app
    cfg = dict(env="test", data_dir=Path(a.data_dir), cookie_secure=False, require_mfa_for_login=False,
               bootstrap_admin_username="root", bootstrap_admin_password=bench.ADMIN_PASSWORD,
               chunk_size_bytes=a.chunk_bytes, storage_timeout_seconds=a.timeout)
    if a.max_upload:
        cfg["max_upload_bytes"] = a.max_upload                   # otherwise the shipped 256 MiB
    if a.detector == "raised":
        cfg["detect_max_download_bytes_in_window"] = 2**50          # count threshold stays at its default
    elif a.detector.startswith("bytes="):
        cfg["detect_max_download_bytes_in_window"] = int(a.detector.split("=", 1)[1])
    providers = None
    if a.providers == "memory":
        cfg["storage_providers"] = "memory-a,memory-b,memory-c"
    else:
        cfg["storage_providers"] = "azure-blob,gcs"                  # disk-backed emulators, R=2 of 2
    settings = Settings(_env_file=None, **cfg)
    if a.providers == "memory":
        from app.storage.memory import MemoryProvider
        providers = {n: MemoryProvider(n) for n in settings.provider_names}
    app = create_app(settings, providers=providers, password_hasher=bench.cheap_hasher())
    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning", access_log=False)


class Running:
    """A fresh server (and, for disk2, emulators) with a monitor for memory, disk and server RSS."""

    def __init__(self, providers: str, *, max_upload: int | None, detector: str, chunk_mib: int = 16, timeout: float = 30.0):
        self.providers, self.max_upload, self.detector, self.chunk_mib, self.timeout = providers, max_upload, detector, chunk_mib, timeout
        self.work = Path(tempfile.mkdtemp(prefix="zt-lim-"))
        self.emu = bench.ManagedEmulators() if providers == "disk2" else None
        self.peak_rss = 0.0
        self.min_avail = 10**9
        self.disk0 = shutil.disk_usage("/").used
        self.peak_disk = 0
        self.aborted = False
        self._stop = threading.Event()

    def __enter__(self):
        import httpx
        env = dict(os.environ)
        if self.emu:
            env.update(self.emu.start())
        self.port = bench.free_port()
        cmd = [sys.executable, str(Path(__file__).resolve()), "serve", "--port", str(self.port), "--data-dir", str(self.work / "data"),
               "--providers", self.providers, "--chunk-bytes", str(self.chunk_mib * MIB), "--timeout", str(self.timeout),
               "--detector", self.detector] + (["--max-upload", str(self.max_upload)] if self.max_upload else [])
        self.srv = subprocess.Popen(cmd, env=env, cwd=bench.BACKEND, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.client = httpx.Client(base_url=f"http://127.0.0.1:{self.port}", timeout=None)
        for _ in range(400):
            if self.srv.poll() is not None:
                raise RuntimeError("server exited: " + self.srv.stderr.read().decode(errors="replace")[-600:])
            try:
                if self.client.get("/api/health").status_code == 200:
                    break
            except httpx.TransportError:
                pass
            time.sleep(0.1)
        r = self.client.post("/api/auth/register", json={"username": "benchuser", "password": bench.PASSWORD})
        assert r.status_code == 202, r.text
        self.thread = threading.Thread(target=self._monitor, daemon=True)
        self.thread.start()
        return self

    def _monitor(self) -> None:
        while not self._stop.is_set():
            try:
                avail = next(int(l.split()[1]) // 1024 for l in Path("/proc/meminfo").read_text().splitlines() if l.startswith("MemAvailable:"))
                self.min_avail = min(self.min_avail, avail)
                rss = bench.vm_hwm_mib(self.srv.pid) or 0
                self.peak_rss = max(self.peak_rss, rss)
                self.peak_disk = max(self.peak_disk, shutil.disk_usage("/").used - self.disk0)
                if avail < MEM_FLOOR_MIB:
                    self.aborted = True
                    self.srv.kill()
                    return
            except Exception:
                pass
            self._stop.wait(2.0)

    def token(self) -> dict:
        r = self.client.post("/api/auth/login", json={"username": "benchuser", "password": bench.PASSWORD})
        assert r.status_code == 200, r.text
        return {"Authorization": "Bearer " + r.json()["access_token"]}

    def upload(self, fileobj, headers: dict):
        return self.client.post("/api/files", headers=headers, files={"file": ("big.bin", fileobj, "application/octet-stream")})

    def audit_rows(self, where: str) -> list:
        db = self.work / "data" / "audit.db"
        try:
            c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            return c.execute(f"select seq, event_type, action, outcome, severity, reason from audit_events where {where} order by seq").fetchall()
        except sqlite3.Error:
            return []

    def __exit__(self, *exc):
        self._stop.set()
        self.srv.terminate()
        try:
            self.srv.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.srv.kill()
        if self.emu:
            self.emu.stop()
        shutil.rmtree(self.work, ignore_errors=True)


def brief(r) -> dict:
    try:
        body = r.json()
    except Exception:
        body = r.text[:200]
    return {"status": r.status_code, "body": body}


# --------------------------------------------------------------------------- #
# defaults: E1, E2, E3
# --------------------------------------------------------------------------- #
def cmd_defaults(a) -> None:
    out: dict = {}
    tmp = Path(tempfile.mkdtemp(prefix="zt-lim-payload-"))
    try:
        big = tmp / "p600.bin"; bench.make_payload(big, 600 * MIB)
        mid = tmp / "p300.bin"; bench.make_payload(mid, 300 * MIB)
        small = tmp / "p1.bin"; bench.make_payload(small, MIB)
        sha600 = bench.sha256_file(big)

        # E1: shipped upload cap (256 MiB), 300 MiB upload
        with Running("memory", max_upload=None, detector="default") as s:
            h = s.token()
            t0 = time.perf_counter()
            with open(mid, "rb") as f:
                r = s.upload(f, h)
            e1 = dict(upload_300MiB=brief(r), seconds=round(time.perf_counter() - t0, 2))
            with open(small, "rb") as f:
                e1["upload_1MiB_after"] = brief(s.upload(f, s.token()))["status"]
            out["E1_default_upload_cap"] = e1
        print("E1", json.dumps(out["E1_default_upload_cap"])[:300], flush=True)

        # E2: cap raised, detector at default
        with Running("memory", max_upload=700 * MIB, detector="default") as s:
            h = s.token()
            with open(big, "rb") as f:
                r = s.upload(f, h)
            e2 = dict(upload_600MiB=brief(r)["status"])
            fid = r.json().get("id")
            r = s.client.get(f"/api/files/{fid}/download", headers=s.token())
            e2["download_600MiB"] = brief(r) if r.status_code != 200 else {"status": 200}
            with open(small, "rb") as f:
                r = s.upload(f, s.token())
            e2["upload_1MiB_after_block"] = r.status_code
            sid = r.json().get("id") if r.status_code == 201 else None
            if sid:
                r = s.client.get(f"/api/files/{sid}/download", headers=s.token())
                e2["download_1MiB_after_block"] = brief(r) if r.status_code != 200 else {"status": 200}
            e2["audit_critical_rows"] = s.audit_rows("severity='critical'")
            out["E2_cap_raised_detector_default"] = e2
        print("E2", json.dumps(out["E2_cap_raised_detector_default"])[:600], flush=True)

        # E3: control, detector raised
        with Running("memory", max_upload=700 * MIB, detector="raised") as s:
            h = s.token()
            with open(big, "rb") as f:
                r = s.upload(f, h)
            fid = r.json().get("id")
            dl = tmp / "dl.bin"
            t0 = time.perf_counter()
            with s.client.stream("GET", f"/api/files/{fid}/download", headers=s.token()) as d:
                code = d.status_code
                with open(dl, "wb") as f:
                    for blk in d.iter_bytes(4 * MIB):
                        f.write(blk)
            out["E3_control_detector_raised"] = dict(upload_600MiB=r.status_code, download_600MiB=code,
                                                     bytes_match=(code == 200 and bench.sha256_file(dl) == sha600),
                                                     seconds=round(time.perf_counter() - t0, 1))
        print("E3", json.dumps(out["E3_control_detector_raised"]), flush=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    d = Path(a.out) if a.out else HERE / "results" / f"phase2-{datetime.now():%Y%m%d}"
    d.mkdir(parents=True, exist_ok=True)
    (d / "defaults.json").write_text(json.dumps(out, indent=1, default=str))
    print(f"[limits] wrote {d / 'defaults.json'}")


# --------------------------------------------------------------------------- #
# big
# --------------------------------------------------------------------------- #
class ThrottledFile:
    """File-like object that reads no faster than rate bytes/s (httpx takes its length from fileno())."""

    def __init__(self, path: Path, rate: float):
        self.f, self.rate, self.t0, self.sent = open(path, "rb"), rate, None, 0

    def fileno(self): return self.f.fileno()
    def seek(self, *a): return self.f.seek(*a)
    def tell(self): return self.f.tell()
    def close(self): self.f.close()

    def read(self, n=-1):
        data = self.f.read(n if n and n > 0 else MIB)
        if not data:
            return data
        if self.t0 is None:
            self.t0 = time.perf_counter()
        self.sent += len(data)
        lag = self.sent / self.rate - (time.perf_counter() - self.t0)
        if lag > 0:
            time.sleep(lag)
        return data


def one_big(size_gib: float, *, slow_mib_s: float | None = None) -> dict:
    size = int(size_gib * GIB)
    tmp = Path(tempfile.mkdtemp(prefix="zt-lim-payload-"))
    res: dict = dict(size_gib=size_gib, slow_mib_s=slow_mib_s)
    try:
        t0 = time.time()
        payload = tmp / "payload.bin"; bench.make_payload(payload, size)
        sha = bench.sha256_file(payload)
        res["prep_s"] = round(time.time() - t0)
        with Running("disk2", max_upload=size + 16 * MIB, detector="raised") as s:
            h = s.token()
            f = ThrottledFile(payload, slow_mib_s * MIB) if slow_mib_s else open(payload, "rb")
            t0 = time.perf_counter()
            try:
                r = s.upload(f, h)
            except Exception as exc:                                     # killed by the memory guard, etc.
                res["upload"] = dict(error=f"{type(exc).__name__}: {str(exc)[:200]}")
                res["aborted_by_memory_guard"] = s.aborted
                return res
            finally:
                f.close()
            t_up = time.perf_counter() - t0
            res["upload"] = dict(status=r.status_code, seconds=round(t_up, 1), mib_s=round(size / MIB / t_up, 1))
            if r.status_code != 201:
                res["upload"]["body"] = r.text[:300]
                return res
            fid = r.json()["id"]
            if slow_mib_s:                                               # the token was issued before an upload that outlived it
                age = time.perf_counter() - t0
                r_old = s.client.get(f"/api/files/{fid}/download", headers=h)
                res["old_token_after_upload"] = dict(token_age_s=round(age), status=r_old.status_code)
            out = tmp / "down.bin"
            t0 = time.perf_counter()
            first = None
            with s.client.stream("GET", f"/api/files/{fid}/download", headers=s.token()) as d:
                res["download_status"] = d.status_code
                with open(out, "wb") as fh:
                    for blk in d.iter_bytes(4 * MIB):
                        if first is None:
                            first = time.perf_counter() - t0
                        fh.write(blk)
            t_dn = time.perf_counter() - t0
            res["download"] = dict(seconds=round(t_dn, 1), mib_s=round(size / MIB / t_dn, 1), ttfb_s=round(first or 0, 1))
            res["bytes_match"] = out.stat().st_size == size and bench.sha256_file(out) == sha
            res["server_peak_rss_mib"] = round(max(s.peak_rss, bench.vm_hwm_mib(s.srv.pid) or 0))
            res["peak_disk_growth_gib"] = round(s.peak_disk / GIB, 1)
            res["min_mem_available_mib"] = s.min_avail
            res["aborted_by_memory_guard"] = s.aborted
        return res
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def cmd_big(a) -> None:
    d = Path(a.out) if a.out else HERE / "results" / f"phase2-{datetime.now():%Y%m%d}"
    d.mkdir(parents=True, exist_ok=True)
    results = []
    plan = [(float(s), None) for s in a.sizes_gib.split(",") if s] + ([(a.slow_gib, a.slow_mib_s)] if a.slow_gib else [])
    for size, slow in plan:
        print(f"[limits] {size:g} GiB{' slow ' + str(slow) + ' MiB/s' if slow else ''} ...", flush=True)
        r = one_big(size, slow_mib_s=slow)
        results.append(r)
        print("   ", json.dumps(r), flush=True)
        (d / "big.json").write_text(json.dumps(dict(env=bench.environment_info(), results=results), indent=1))
    print(f"[limits] wrote {d / 'big.json'}")


def cmd_boundary(a) -> None:
    """Detector boundary at the chosen deployment value: with a byte threshold of T, files of size S
    (S <= T < 3S) should download twice and be blocked on the third attempt within the window."""
    import hashlib
    size, thr = int(a.size_gib * GIB), int(a.threshold_gib * GIB)
    tmp = Path(tempfile.mkdtemp(prefix="zt-lim-payload-"))
    res: dict = dict(size_gib=a.size_gib, threshold_gib=a.threshold_gib)
    try:
        payload = tmp / "payload.bin"; bench.make_payload(payload, size)
        sha = bench.sha256_file(payload)
        with Running("disk2", max_upload=size + 16 * MIB, detector=f"bytes={thr}") as s:
            with open(payload, "rb") as f:
                r = s.upload(f, s.token())
            res["upload_status"] = r.status_code
            fid = r.json()["id"]
            for i in (1, 2, 3):
                h = hashlib.sha256()
                n = 0
                t0 = time.perf_counter()
                with s.client.stream("GET", f"/api/files/{fid}/download", headers=s.token()) as d:
                    code = d.status_code
                    if code == 200:
                        for blk in d.iter_bytes(4 * MIB):
                            n += len(blk)
                            h.update(blk)
                    else:
                        d.read()
                        res[f"download_{i}_body"] = d.text[:200]
                res[f"download_{i}"] = dict(status=code, seconds=round(time.perf_counter() - t0, 1),
                                            bytes_match=(code == 200 and n == size and h.hexdigest() == sha))
                print("   ", i, json.dumps(res[f"download_{i}"]), flush=True)
            res["audit_critical_rows"] = s.audit_rows("severity='critical'")
            res["server_peak_rss_mib"] = round(max(s.peak_rss, bench.vm_hwm_mib(s.srv.pid) or 0))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    d = Path(a.out) if a.out else HERE / "results" / f"phase2-{datetime.now():%Y%m%d}"
    d.mkdir(parents=True, exist_ok=True)
    (d / "boundary.json").write_text(json.dumps(res, indent=1, default=str))
    print(json.dumps(res, default=str)[:900])
    print(f"[limits] wrote {d / 'boundary.json'}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    bp = sub.add_parser("boundary")
    bp.add_argument("--size-gib", type=float, default=10)
    bp.add_argument("--threshold-gib", type=float, default=20)
    bp.add_argument("--out")
    for n in ("defaults", "big"):
        p = sub.add_parser(n)
        p.add_argument("--out")
        if n == "big":
            p.add_argument("--sizes-gib", default="2,5,10")
            p.add_argument("--slow-gib", type=float, default=3)
            p.add_argument("--slow-mib-s", type=float, default=8)
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, required=True)
    s.add_argument("--data-dir", required=True)
    s.add_argument("--providers", required=True)
    s.add_argument("--chunk-bytes", type=int, required=True)
    s.add_argument("--timeout", type=float, required=True)
    s.add_argument("--detector", default="default")
    s.add_argument("--max-upload", type=int, default=0)
    a = ap.parse_args()
    {"defaults": cmd_defaults, "big": cmd_big, "boundary": cmd_boundary, "serve": cmd_serve}[a.cmd](a)


if __name__ == "__main__":
    main()
