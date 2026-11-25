#!/usr/bin/env python3
"""Phase 4: benchmark the backend against REAL S3, Azure Blob and GCS (or rehearse on emulators).

For each file size it measures (a) our backend end to end (R=2 of 3 providers, chosen chunk sizes)
and (b) a direct single-object put/get to each provider through the same SDK adapter, from the
same host, as a baseline. The baseline isolates what chunking, encryption, replication with
read-back verification, policy and audit add on top of the raw provider transfer.

  plan        no network, no credentials: exact data volumes, request counts and (with your prices) cost
  preflight   checks credentials, bucket names, emptiness and latency; creates and deletes tiny objects
  run         the benchmark; refuses to start if the plan exceeds --max-transfer-gib
  summarize   markdown tables from a results directory
  cleanup     empties the three buckets (needs --yes-empty-buckets with the exact names)

Targets:  --target emulators   rehearsal on local emulators (costs nothing; use it to test the tool)
          --target real        real providers; configured ONLY through environment variables:
    S3     ZT_S3_BUCKET, ZT_S3_REGION, and credentials (AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY, or
           ZT_S3_ACCESS_KEY_ID + ZT_S3_SECRET_ACCESS_KEY, or AWS_PROFILE)
    Azure  ZT_AZURE_CONNECTION_STRING, ZT_AZURE_CONTAINER   (use a DEDICATED storage account)
    GCS    ZT_GCS_BUCKET, ZT_GCS_PROJECT (optional), GOOGLE_APPLICATION_CREDENTIALS (service-account key file)

Safety rules enforced for --target real:
  * all three bucket/container names must contain "bench" (so a production bucket cannot be used or emptied);
  * the buckets must be EMPTY at the start (cleanup deletes every object in them);
  * emulator endpoints must be unset; the Azure development account is refused;
  * secrets are checked for presence only and are never printed or written to results;
  * a byte budget (--max-transfer-gib) aborts the run before it is exceeded.

Run from the backend directory with the project venv.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import os
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import bench  # noqa: E402

MIB = bench.MIB
GIB = 1024 * MIB
PROVS = ("aws-s3", "azure-blob", "gcs")


# --------------------------------------------------------------------------- #
# volume model (used by `plan` and the budget guard)
# --------------------------------------------------------------------------- #
def volumes(kind: str, size: int, chunk: int = 0) -> dict:
    """Bytes into and out of the clouds, and request counts, for ONE measurement."""
    if kind == "backend":
        n = math.ceil(size / chunk)
        # upload writes each chunk to 2 providers and reads each back to verify; download reads one replica
        return dict(ingress=2 * size, egress=2 * size + size, put=2 * n, get=2 * n + n, delete=2 * n)
    return dict(ingress=size, egress=size, put=1, get=1, delete=1)       # direct: one provider


def build_plan(a) -> dict:
    sizes = [int(float(s) * MIB) for s in a.sizes_mib.split(",")]
    chunks = [int(c) * MIB for c in a.chunks_mib.split(",")]
    tot = dict(ingress=0, egress=0, put=0, get=0, delete=0, measurements=0)
    rows = []
    for s in sizes:
        reps = a.repeats_large if s >= GIB else a.repeats
        for c in chunks:
            v = volumes("backend", s, c)
            rows.append((f"backend {c // MIB} MiB chunks", s, reps, v))
        if s <= a.baseline_max_mib * MIB:
            for _ in PROVS:
                rows.append(("direct (per provider)", s, reps, volumes("direct", s)))
    for _label, _s, reps, v in rows:
        for k in ("ingress", "egress", "put", "get", "delete"):
            tot[k] += v[k] * reps
        tot["measurements"] += reps
    return dict(rows=rows, total=tot)


def cmd_plan(a) -> None:
    plan = build_plan(a)
    t = plan["total"]
    print(f"Plan: sizes {a.sizes_mib} MiB, backend chunk sizes {a.chunks_mib} MiB, {a.repeats} repeats ({a.repeats_large} at 1 GiB and above), "
          f"direct baseline up to {a.baseline_max_mib} MiB\n")
    print(f"{'configuration':28} {'size MiB':>9} {'reps':>5} {'into clouds GiB':>16} {'out of clouds GiB':>18} {'PUT':>7} {'GET':>7}")
    for label, s, reps, v in plan["rows"]:
        print(f"{label:28} {s / MIB:9.0f} {reps:5d} {v['ingress'] * reps / GIB:16.2f} {v['egress'] * reps / GIB:18.2f} {v['put'] * reps:7d} {v['get'] * reps:7d}")
    print(f"\nTOTAL: {t['measurements']} measurements; {t['ingress'] / GIB:.1f} GiB into the clouds, {t['egress'] / GIB:.1f} GiB out of the clouds; "
          f"{t['put']} PUT-class, {t['get']} GET-class, {t['delete']} DELETE requests (plus listing and a few anchor/audit objects).")
    print("'Out of the clouds' is what providers usually bill as egress. It is zero between a VM and a bucket in the SAME region of the SAME provider, "
          "but not for the other two providers.")
    if a.price_egress_gib or a.price_ingress_gib or a.price_per_1000_requests:
        cost = (t["egress"] / GIB * a.price_egress_gib + t["ingress"] / GIB * a.price_ingress_gib
                + (t["put"] + t["get"] + t["delete"]) / 1000 * a.price_per_1000_requests)
        print(f"Illustrative cost at YOUR prices (egress {a.price_egress_gib}/GiB, ingress {a.price_ingress_gib}/GiB, "
              f"{a.price_per_1000_requests}/1000 requests): {cost:.2f} (your currency). Prices vary by provider, region and tier; check the current price lists. Storage during the run is negligible.")
    else:
        print("Pass --price-egress-gib, --price-ingress-gib and --price-per-1000-requests (from your own price lists) to see an estimate.")
    print(f"Budget guard for `run`: --max-transfer-gib must be at least {math.ceil((t['ingress'] + t['egress']) / GIB)} for this plan.")


# --------------------------------------------------------------------------- #
# targets, credentials, safety checks
# --------------------------------------------------------------------------- #
def missing_real_env() -> list[str]:
    e, m = os.environ, []
    if not e.get("ZT_S3_BUCKET"):
        m.append("ZT_S3_BUCKET")
    if not ((e.get("AWS_ACCESS_KEY_ID") and e.get("AWS_SECRET_ACCESS_KEY")) or (e.get("ZT_S3_ACCESS_KEY_ID") and e.get("ZT_S3_SECRET_ACCESS_KEY")) or e.get("AWS_PROFILE")):
        m.append("AWS credentials (AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY, or ZT_S3_ACCESS_KEY_ID + ZT_S3_SECRET_ACCESS_KEY, or AWS_PROFILE)")
    for k in ("ZT_AZURE_CONNECTION_STRING", "ZT_AZURE_CONTAINER", "ZT_GCS_BUCKET"):
        if not e.get(k):
            m.append(k)
    g = e.get("GOOGLE_APPLICATION_CREDENTIALS")
    if not g or not Path(g).is_file():
        m.append("GOOGLE_APPLICATION_CREDENTIALS (path to an existing service-account key file)")
    for k in ("ZT_S3_ENDPOINT_URL", "ZT_GCS_ENDPOINT_URL"):
        if e.get(k):
            m.append(f"{k} must be UNSET for a real run (it points at an emulator)")
    cs = e.get("ZT_AZURE_CONNECTION_STRING", "")
    if "devstoreaccount1" in cs or "UseDevelopmentStorage" in cs:
        m.append("ZT_AZURE_CONNECTION_STRING is the local Azurite development account")
    return m


def bucket_names() -> list[str]:
    e = os.environ
    return [e.get("ZT_S3_BUCKET", ""), e.get("ZT_AZURE_CONTAINER", ""), e.get("ZT_GCS_BUCKET", "")]


def open_target(a):
    """Returns (env overrides for the backend process, teardown callable)."""
    if a.target == "emulators":
        emu = bench.ManagedEmulators()
        env = emu.start()
        os.environ.update(env)
        return env, emu.stop
    miss = missing_real_env()
    if miss:
        sys.exit("Cannot start a real run. Missing or wrong:\n  - " + "\n  - ".join(miss) + "\n(No values are printed. Nothing was contacted.)")
    bad = [n for n in bucket_names() if "bench" not in n.lower()]
    if bad and not a.allow_any_bucket_name:
        sys.exit(f"Refusing: bucket/container name(s) without 'bench': {bad}. `cleanup` deletes EVERYTHING in these buckets, so use dedicated, "
                 "disposable ones named with 'bench' (or pass --allow-any-bucket-name if you are certain).")
    return {}, (lambda: None)


def make_providers(timeout: float):
    from app.config import Settings
    from app.storage import build_providers
    # data_dir is never created or used here (only the provider settings matter), so do not make a directory for it
    s = Settings(_env_file=None, env="test", data_dir=Path(tempfile.gettempdir()) / f"zt-rc-cfg-{uuid.uuid4().hex}",
                 storage_providers=",".join(PROVS), storage_timeout_seconds=timeout)
    return build_providers(s)


def empty_all(providers: dict) -> dict:
    counts = {}
    for name, p in providers.items():
        keys = list(p.list_keys(""))
        for k in keys:
            p.delete(k)
        left = list(itertools.islice(p.list_keys(""), 3))
        if left:
            raise RuntimeError(f"cleanup failed on {name}: objects remain")
        counts[name] = len(keys)
    return counts


class Budget:
    def __init__(self, cap_gib: float | None):
        self.cap = cap_gib * GIB if cap_gib else None
        self.moved = 0

    def charge(self, v: dict) -> None:
        self.moved += v["ingress"] + v["egress"]
        if self.cap is not None and self.moved > self.cap:
            raise SystemExit(f"Budget cap reached: the next measurement would bring the total to {self.moved / MIB:.0f} MiB, above "
                             f"--max-transfer-gib ({self.cap / MIB:.0f} MiB). Stopping before it runs.")


# --------------------------------------------------------------------------- #
# preflight
# --------------------------------------------------------------------------- #
def cmd_preflight(a) -> None:
    env, teardown = open_target(a)
    try:
        providers = make_providers(60.0)
        ok = True
        for name, p in providers.items():
            h = p.health()
            nonempty = list(itertools.islice(p.list_keys(""), 5))
            lat = []
            for _ in range(10):
                k = f"bench-preflight-{uuid.uuid4().hex}"
                t0 = time.perf_counter(); p.put(k, b"x" * 1024); t1 = time.perf_counter(); p.get(k); t2 = time.perf_counter(); p.delete(k); t3 = time.perf_counter()
                lat.append((t1 - t0, t2 - t1, t3 - t2))
            blob = os.urandom(8 * MIB); k = f"bench-preflight-{uuid.uuid4().hex}"
            t0 = time.perf_counter(); p.put(k, blob); tp = time.perf_counter() - t0
            t0 = time.perf_counter(); got = p.get(k); tg = time.perf_counter() - t0; p.delete(k)
            same = got == blob
            med = lambda i: statistics.median(x[i] for x in lat) * 1000
            print(f"{name:11} healthy={h.healthy} empty={not nonempty} 1KiB put/get/delete median {med(0):.0f}/{med(1):.0f}/{med(2):.0f} ms; "
                  f"8 MiB put {8 / tp:.1f} MiB/s, get {8 / tg:.1f} MiB/s; roundtrip ok={same}")
            ok &= bool(h.healthy and not nonempty and same)
        print("PREFLIGHT " + ("OK" if ok else "FAILED (see above; buckets must be healthy, empty and round-trip correctly)"))
        if not ok:
            sys.exit(1)
    finally:
        teardown()


# --------------------------------------------------------------------------- #
# server (backend under test) and measurements
# --------------------------------------------------------------------------- #
def cmd_serve(a) -> None:
    import uvicorn

    from app.config import Settings
    from app.main import create_app
    cfg = bench.settings_kwargs(Path(a.data_dir), a.chunk_bytes, a.max_upload, "emulators")   # providers come from the environment
    cfg["storage_providers"] = ",".join(PROVS)
    cfg["storage_timeout_seconds"] = a.timeout
    settings = Settings(_env_file=None, **cfg)
    app = create_app(settings, password_hasher=bench.cheap_hasher())
    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning", access_log=False)


def measure_backend(env_over: dict, size_mib: float, chunk_mib: int, payload: Path, sha: str, warm: Path, timeout: float) -> dict:
    import httpx
    size = int(size_mib * MIB)
    work = Path(tempfile.mkdtemp(prefix="zt-rc-"))
    env = {**os.environ, **env_over}
    port = bench.free_port()
    srv = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "serve", "--port", str(port), "--data-dir", str(work / "data"),
                            "--chunk-bytes", str(chunk_mib * MIB), "--max-upload", str(size + 16 * MIB), "--timeout", str(timeout)],
                           env=env, cwd=bench.BACKEND, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        c = httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=None)
        for _ in range(600):
            if srv.poll() is not None:
                raise RuntimeError("server exited: " + srv.stderr.read().decode(errors="replace")[-400:])
            try:
                if c.get("/api/health").status_code == 200:
                    break
            except httpx.TransportError:
                pass
            time.sleep(0.1)
        assert c.post("/api/auth/register", json={"username": "benchuser", "password": bench.PASSWORD}).status_code == 202

        def token() -> dict:
            r = c.post("/api/auth/login", json={"username": "benchuser", "password": bench.PASSWORD})
            return {"Authorization": "Bearer " + r.json()["access_token"]}

        def upload(path: Path, h: dict):
            with open(path, "rb") as f:
                return c.post("/api/files", headers=h, files={"file": ("bench.bin", f, "application/octet-stream")})

        h = token(); r = upload(warm, h); assert r.status_code == 201, r.text[:200]
        with c.stream("GET", f"/api/files/{r.json()['id']}/download", headers=h) as d:
            for _ in d.iter_bytes(MIB):
                pass
        h = token()
        t0 = time.perf_counter(); r = upload(payload, h); t_up = time.perf_counter() - t0
        assert r.status_code == 201, f"upload {r.status_code} {r.text[:200]}"
        fid = r.json()["id"]
        out = work / "down.bin"; first = None
        h = token()
        t0 = time.perf_counter()
        with c.stream("GET", f"/api/files/{fid}/download", headers=h) as d:
            assert d.status_code == 200, d.status_code
            with open(out, "wb") as f:
                for blk in d.iter_bytes(4 * MIB):
                    if first is None:
                        first = time.perf_counter() - t0
                    f.write(blk)
        t_dn = time.perf_counter() - t0
        return dict(upload_s=t_up, download_s=t_dn, ttfb_s=first, verified=out.stat().st_size == size and bench.sha256_file(out) == sha,
                    server_peak_rss_mib=bench.vm_hwm_mib(srv.pid))
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=60)
        except subprocess.TimeoutExpired:
            srv.kill()
        shutil.rmtree(work, ignore_errors=True)


def measure_direct(p, data: bytes, sha: str) -> dict:
    key = f"bench-direct-{uuid.uuid4().hex}"
    t0 = time.perf_counter(); p.put(key, data); t_up = time.perf_counter() - t0
    t0 = time.perf_counter(); got = p.get(key); t_dn = time.perf_counter() - t0
    ok = hashlib.sha256(got).hexdigest() == sha
    p.delete(key)
    return dict(upload_s=t_up, download_s=t_dn, ttfb_s=None, verified=ok, server_peak_rss_mib=None)


def cmd_run(a) -> None:
    plan = build_plan(a)["total"]
    need = (plan["ingress"] + plan["egress"]) / GIB
    if a.target == "real" and (not a.max_transfer_gib or a.max_transfer_gib < need):
        sys.exit(f"Refusing: this plan moves about {need:.1f} GiB. Pass --max-transfer-gib >= {math.ceil(need)} (run `plan` first) to confirm you accept that volume.")
    env_over, teardown = open_target(a)
    budget = Budget(a.max_transfer_gib)
    out = Path(a.out) if a.out else HERE / "results" / f"phase4-{a.target}-{datetime.now():%Y%m%d-%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    meta = dict(env=bench.environment_info(), target=a.target, host_label=a.host_label, plan=vars(a),
                regions=dict(s3=os.environ.get("ZT_S3_REGION"), gcs_project_set=bool(os.environ.get("ZT_GCS_PROJECT"))),
                started=datetime.now().astimezone().isoformat(timespec="seconds"))
    meta["plan"].pop("price_egress_gib", None)
    (out / "meta.json").write_text(json.dumps(meta, indent=1, default=str))
    sizes = [(float(s), a.repeats_large if float(s) * MIB >= GIB else a.repeats) for s in a.sizes_mib.split(",")]
    chunks = [int(c) for c in a.chunks_mib.split(",")]
    configs = [("backend", str(c)) for c in chunks] + [("direct", p) for p in PROVS]
    tmp = Path(tempfile.mkdtemp(prefix="zt-rc-payload-"))
    warm = tmp / "warm.bin"; bench.make_payload(warm, MIB)
    rows_path = out / "measurements.jsonl"
    consecutive_failures = 0
    try:
        for size_mib, reps in sizes:
            size = int(size_mib * MIB)
            payload = tmp / f"p{size_mib:g}.bin"; bench.make_payload(payload, size)
            sha = bench.sha256_file(payload)
            data = payload.read_bytes() if size_mib <= a.baseline_max_mib else None
            for r in range(reps):
                order = configs[r % len(configs):] + configs[:r % len(configs)]
                for kind, label in order:
                    if kind == "direct" and data is None:
                        continue
                    budget.charge(volumes("backend", size, int(label) * MIB) if kind == "backend" else volumes("direct", size))
                    timeout = max(30.0, size_mib * 2) if kind == "direct" else 30.0
                    providers = make_providers(max(120.0, size_mib * 2))
                    try:
                        try:
                            m = measure_backend(env_over, size_mib, int(label), payload, sha, warm, timeout) if kind == "backend" else measure_direct(providers[label], data, sha)
                        except Exception as exc:                  # a transient provider error or a missed deadline is a result, not a crash
                            m = dict(failed=True, error=f"{type(exc).__name__}: {str(exc)[:300]}", upload_s=None, download_s=None,
                                     ttfb_s=None, verified=False, server_peak_rss_mib=None)
                    finally:
                        removed = empty_all(providers)            # delete everything this measurement created, and verify the buckets are empty
                    m.update(kind=kind, label=label, size_mib=size_mib, rep=r, objects_removed=sum(removed.values()))
                    with open(rows_path, "a") as f:
                        f.write(json.dumps(m) + "\n")
                    if m.get("failed"):
                        consecutive_failures += 1
                        print(f"[realcloud] {size_mib:g} MiB rep {r + 1}/{reps} {kind}:{label} FAILED ({consecutive_failures} in a row): {m['error'][:160]}", flush=True)
                        if consecutive_failures >= 3:
                            raise SystemExit("3 measurements failed in a row; stopping. Objects were cleaned up. See measurements.jsonl for the errors.")
                        continue
                    consecutive_failures = 0
                    print(f"[realcloud] {size_mib:g} MiB rep {r + 1}/{reps} {kind}:{label} up {m['upload_s']:.2f}s down {m['download_s']:.2f}s "
                          f"verified={m['verified']} removed={m['objects_removed']} moved={budget.moved / GIB:.2f} GiB", flush=True)
            payload.unlink()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        teardown()
    print(f"[realcloud] wrote {out}")


def cmd_summarize(a) -> None:
    d = Path(a.dir)
    all_rows = [json.loads(l) for l in (d / "measurements.jsonl").read_text().splitlines() if l.strip()]
    rows = [r for r in all_rows if not r.get("failed")]
    failed = [r for r in all_rows if r.get("failed")]
    meta = json.loads((d / "meta.json").read_text())
    print(f"# Real-cloud benchmark ({meta['target']}, host: {meta['host_label'] or 'unlabelled'})\n")
    print(f"Measurements: {len(rows)} completed, {len(failed)} failed. Unverified transfers among completed: {sum(1 for r in rows if not r['verified'])}. "
          f"Cells are median [min-max] MiB/s over n completed runs.\n")
    for r in failed[:10]:
        print(f"- FAILED {r['size_mib']:g} MiB {r['kind']}:{r['label']} rep {r['rep'] + 1}: {r['error'][:200]}")
    if failed:
        print()
    print("| File | Configuration | n | Upload MiB/s | Download MiB/s |\n|---:|---|---:|---:|---:|")
    groups: dict = {}
    for r in rows:
        groups.setdefault((r["size_mib"], r["kind"], r["label"]), []).append(r)
    for (s, kind, label), rs in sorted(groups.items()):
        up = [s / r["upload_s"] for r in rs]; dn = [s / r["download_s"] for r in rs]
        f = lambda xs: f"{statistics.median(xs):.1f} [{min(xs):.1f}-{max(xs):.1f}]"
        name = f"backend, {label} MiB chunks" if kind == "backend" else f"direct to {label}"
        print(f"| {s:g} MiB | {name} | {len(rs)} | {f(up)} | {f(dn)} |")


def cmd_cleanup(a) -> None:
    names = [n for n in bucket_names() if n]
    if a.yes_empty_buckets != ",".join(names):
        sys.exit("Refusing. To delete EVERY object in these buckets pass exactly: --yes-empty-buckets " + ",".join(names))
    env, teardown = open_target(a)
    try:
        print("deleted objects:", empty_all(make_providers(120.0)))
    finally:
        teardown()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, plan_args=True):
        p.add_argument("--target", choices=("emulators", "real"), default="emulators")
        p.add_argument("--allow-any-bucket-name", action="store_true")
        if plan_args:
            p.add_argument("--sizes-mib", default="10,40,100,1024")
            p.add_argument("--chunks-mib", default="1,16")
            p.add_argument("--repeats", type=int, default=5)
            p.add_argument("--repeats-large", type=int, default=3, help="repeats for files of 1 GiB and above")
            p.add_argument("--baseline-max-mib", type=float, default=1024, help="largest file for the direct single-object baseline (held in memory)")
    pl = sub.add_parser("plan"); common(pl)
    pl.add_argument("--price-egress-gib", type=float, default=0); pl.add_argument("--price-ingress-gib", type=float, default=0)
    pl.add_argument("--price-per-1000-requests", type=float, default=0)
    pf = sub.add_parser("preflight"); common(pf, False)
    ru = sub.add_parser("run"); common(ru)
    ru.add_argument("--max-transfer-gib", type=float, default=0); ru.add_argument("--host-label", default=""); ru.add_argument("--out")
    su = sub.add_parser("summarize"); su.add_argument("dir")
    cl = sub.add_parser("cleanup"); common(cl, False); cl.add_argument("--yes-empty-buckets", default="")
    sv = sub.add_parser("serve")
    sv.add_argument("--port", type=int, required=True); sv.add_argument("--data-dir", required=True)
    sv.add_argument("--chunk-bytes", type=int, required=True); sv.add_argument("--max-upload", type=int, required=True); sv.add_argument("--timeout", type=float, required=True)
    a = ap.parse_args()
    {"plan": cmd_plan, "preflight": cmd_preflight, "run": cmd_run, "summarize": cmd_summarize, "cleanup": cmd_cleanup, "serve": cmd_serve}[a.cmd](a)


if __name__ == "__main__":
    main()
