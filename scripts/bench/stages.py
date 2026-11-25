#!/usr/bin/env python3
"""Phase 1b: deterministic stage timing of one upload / download (no sampling).

Runs the real server (loopback, like bench.py) with wall-clock timers wrapped around
the functions that matter. The wrapping happens only inside this benchmark's server
process, at runtime: no application file is modified. For each timer we keep, per
thread kind, the call count, INCLUSIVE seconds and EXCLUSIVE ("self") seconds, where
exclusive excludes timers nested inside it on the same thread.

The request thread (anyio worker) executes upload/download sequentially, so its
exclusive times add up to the service call's wall time: that is a clean breakdown
of the critical path. Work done on other threads (provider fan-out, deadline
runner) is reported separately as thread-seconds.

  cd backend
  .venv/bin/python ../scripts/bench/stages.py run --providers memory --size-mib 100 --repeats 3
  .venv/bin/python ../scripts/bench/stages.py run --providers emulators --size-mib 100 --repeats 3

Internal: `serve` is the instrumented server (SIGUSR1 dumps+resets, SIGUSR2 resets).
"""
from __future__ import annotations

import argparse
import functools
import json
import os
import shutil
import signal
import statistics
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


# --------------------------------------------------------------------------- #
# timers (server side)
# --------------------------------------------------------------------------- #
class Registry:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.tls = threading.local()
        self.data: dict[str, list[float]] = {}
        self.dumps = 0

    @staticmethod
    def kind() -> str:
        n = threading.current_thread().name
        if n == "MainThread":
            return "loop"
        if n.startswith("AnyIO") or n.startswith("asyncio") or n.startswith("ThreadPool"):
            return "request"
        if n.startswith("zt-storage-fanout"):
            return "fanout"
        if n.startswith("zt-storage"):
            return "io"
        return "other"

    def reset(self) -> None:
        with self.lock:
            self.data = {}

    def add(self, key: str, incl: float, excl: float) -> None:
        with self.lock:
            e = self.data.setdefault(key, [0, 0.0, 0.0])
            e[0] += 1
            e[1] += incl
            e[2] += excl

    def dump(self, path: Path) -> None:
        with self.lock:
            snap = {k: list(v) for k, v in self.data.items()}
            self.data = {}
        path.write_text(json.dumps(snap))


REG = Registry()


def timed(name: str, fn):
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        stack = REG.tls.__dict__.setdefault("stack", [])
        frame = [0.0]
        stack.append(frame)
        t0 = time.perf_counter()
        try:
            return fn(*a, **kw)
        finally:
            dt = time.perf_counter() - t0
            stack.pop()
            if stack:
                stack[-1][0] += dt
            REG.add(f"{REG.kind()}|{name}", dt, dt - frame[0])
    return wrapper


def timed_gen(name: str, fn):
    """Time each `next()` of a generator function (the consumer's wait for the next item)."""
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        it = fn(*a, **kw)
        while True:
            stack = REG.tls.__dict__.setdefault("stack", [])
            frame = [0.0]
            stack.append(frame)
            t0 = time.perf_counter()
            try:
                item = next(it)
            except StopIteration:
                return
            finally:
                dt = time.perf_counter() - t0
                stack.pop()
                if stack:
                    stack[-1][0] += dt
                REG.add(f"{REG.kind()}|{name}", dt, dt - frame[0])
            yield item
    return wrapper


def install_timers() -> None:
    import app.api.upload as upload_mod
    import app.audit.service as audit_mod
    import app.cryptoengine.assembler as asm
    import app.cryptoengine.chunks as chunks
    import app.cryptoengine.engine as engine
    import app.files.service as files
    import app.storage.orchestrator as orch
    import sqlalchemy.orm as sa_orm

    def patch(obj, attr, label, gen=False):
        if hasattr(obj, attr):
            setattr(obj, attr, (timed_gen if gen else timed)(label, getattr(obj, attr)))

    # ---- upload critical path
    patch(files.FileService, "upload", "SERVICE upload() total")
    patch(chunks, "iter_plain_chunks", "read body + split into chunks (iterator wait)", gen=True)
    patch(upload_mod.StreamingMultipart, "read", "  of which: multipart read() (waits on network)")
    patch(chunks.PlaintextAccumulator, "update", "SHA-256 of plaintext (whole-file hash)")
    patch(chunks, "encrypt_chunk", "encrypt_chunk (AES-256-GCM + SHA-256 of blob)")
    patch(sa_orm.Session, "commit", "metadata DB commit (SQLite)")
    patch(orch.StorageOrchestrator, "store_chunk", "store_chunk (replicate to R providers)")
    patch(orch.StorageOrchestrator, "_audit_event", "audit event raised by orchestrator")
    patch(audit_mod.AuditService, "_append", "audit append (SQLite insert + commit)")
    patch(audit_mod.AuditService, "record", "audit record() total")
    # ---- download critical path
    patch(files.FileService, "download", "SERVICE download() total")
    patch(files.FileService, "_authorize", "authorize (policy + DB read + audit)")
    patch(files.FileService, "_open", "open manifest + unwrap key (KMS)")
    patch(engine.CryptoEngine, "assemble", "assemble (loop: fetch, decrypt, hash, spool)")
    patch(asm, "decrypt_chunk", "decrypt_chunk (SHA-256 check + AES-256-GCM)")
    patch(orch.StorageOrchestrator, "fetch_chunk", "fetch_chunk (get replica + verify SHA-256)")
    # ---- providers (run on pool threads)
    for modname, cls in (("app.storage.memory", "MemoryProvider"), ("app.storage.s3", "S3Provider"),
                         ("app.storage.azure", "AzureBlobProvider"), ("app.storage.gcs", "GCSProvider")):
        try:
            mod = __import__(modname, fromlist=[cls])
        except Exception:
            continue
        klass = getattr(mod, cls, None)
        if klass is not None:
            patch(klass, "put", f"provider put ({cls})")
            patch(klass, "get", f"provider get ({cls})")


def cmd_serve(a) -> None:
    import uvicorn

    from app.config import Settings
    from app.main import create_app
    install_timers()
    out = Path(os.environ["ZT_STAGE_OUT"])

    def on_dump(_s, _f):
        REG.dumps += 1
        REG.dump(out / f"stages-{REG.dumps}.json")

    signal.signal(signal.SIGUSR1, on_dump)
    signal.signal(signal.SIGUSR2, lambda _s, _f: REG.reset())
    cfg = bench.settings_kwargs(Path(a.data_dir), a.chunk_bytes, a.max_upload, a.providers)
    settings = Settings(_env_file=None, **cfg)
    providers = None
    if a.providers == "memory":
        from app.storage.memory import MemoryProvider
        providers = {n: MemoryProvider(n) for n in settings.provider_names}
    app = create_app(settings, providers=providers, password_hasher=bench.cheap_hasher())
    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning", access_log=False)


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #
def cmd_run(a) -> None:
    import httpx
    size = int(a.size_mib * MIB)
    out = Path(a.out) if a.out else HERE / "results" / f"stages-{datetime.now():%Y%m%d-%H%M%S}-{a.providers}"
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="zt-stages-"))
    emu = bench.ManagedEmulators() if a.providers == "emulators" else None
    env = dict(os.environ)
    if emu:
        env.update(emu.start())
    env["ZT_STAGE_OUT"] = str(out)
    for old in out.glob("stages-*.json"):
        old.unlink()
    port = bench.free_port()
    srv = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "serve", "--port", str(port),
                            "--data-dir", str(work / "data"), "--providers", a.providers,
                            "--chunk-bytes", str(int(a.chunk_mib * MIB)), "--max-upload", str(size + 16 * MIB)],
                           env=env, cwd=bench.BACKEND, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    walls: list[tuple[float, float]] = []
    try:
        c = httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=None)
        for _ in range(400):
            if srv.poll() is not None:
                sys.exit("server exited: " + srv.stderr.read().decode(errors="replace")[-1200:])
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

        payload = work / "payload.bin"
        bench.make_payload(payload, size)

        def one() -> tuple[float, float, str]:
            h = token()
            t0 = time.perf_counter()
            with open(payload, "rb") as f:
                r = c.post("/api/files", headers=h, files={"file": ("bench.bin", f, "application/octet-stream")})
            t_up = time.perf_counter() - t0
            assert r.status_code == 201, r.text[:300]
            fid = r.json()["id"]
            return t_up, 0.0, fid

        def down(fid: str) -> float:
            h = token()
            t0 = time.perf_counter()
            with c.stream("GET", f"/api/files/{fid}/download", headers=h) as d:
                for _ in d.iter_bytes(4 * MIB):
                    pass
            return time.perf_counter() - t0

        def wait_dump(n: int) -> dict:
            p = out / f"stages-{n}.json"
            for _ in range(200):
                if p.exists():
                    try:
                        return json.loads(p.read_text())
                    except json.JSONDecodeError:
                        pass
                time.sleep(0.05)
            raise RuntimeError(f"no stage dump {n}")

        fid = one()[2]; down(fid)                     # warm-up, untimed
        os.kill(srv.pid, signal.SIGUSR2)
        time.sleep(0.2)
        dumps_up, dumps_down, n = [], [], 0
        for _ in range(a.repeats):
            t_up, _, fid = one()
            n += 1; os.kill(srv.pid, signal.SIGUSR1); dumps_up.append(wait_dump(n))
            t_dn = down(fid)
            n += 1; os.kill(srv.pid, signal.SIGUSR1); dumps_down.append(wait_dump(n))
            walls.append((t_up, t_dn))
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=30)
        except subprocess.TimeoutExpired:
            srv.kill()
        if emu:
            emu.stop()
        shutil.rmtree(work, ignore_errors=True)
    md = render(a, walls, dumps_up, dumps_down)
    (out / "stages.md").write_text(md)
    print(md)
    print(f"[stages] wrote {out}")


def med(vals):
    return statistics.median(vals) if vals else 0.0


def render(a, walls, ups, downs) -> str:
    out = [f"# Stage timing: {a.providers} providers, {a.size_mib:g} MiB, chunk {a.chunk_mib:g} MiB, "
           f"{a.repeats} timed repeats (median)\n",
           "Wrapped with wall-clock timers inside the benchmark server only (no application file changed). "
           "Timers add a little overhead of their own (a few microseconds per call). "
           "Exclusive = time in that function excluding timers nested inside it on the same thread. "
           "Request-thread exclusive times add up to the service call's wall time.\n"]
    for title, dumps, client_wall, svc_key in (
            ("Upload", ups, med([w[0] for w in walls]), "request|SERVICE upload() total"),
            ("Download", downs, med([w[1] for w in walls]), "request|SERVICE download() total")):
        keys = sorted({k for d in dumps for k in d})
        agg = {k: [med([d.get(k, [0, 0, 0])[i] for d in dumps]) for i in range(3)] for k in keys}
        svc = agg.get(svc_key, [0, 0, 0])[1]
        out.append(f"\n## {title}\n")
        out.append(f"- Client-measured wall time (whole HTTP request): **{client_wall*1000:.0f} ms**")
        if svc:
            out.append(f"- Time inside the service call (`{svc_key.split('|')[1]}`): **{svc*1000:.0f} ms** "
                       f"({100*svc/client_wall:.0f}% of wall); the other {(client_wall-svc)*1000:.0f} ms is HTTP/framework work "
                       f"outside the service call (receiving or sending the body, routing, auth middleware, response)")
        req = [(k, v) for k, v in agg.items() if k.startswith("request|") and k != svc_key]
        req.sort(key=lambda kv: -kv[1][2])
        out.append("\n**Request thread, by exclusive time** (the critical path):\n")
        out.append("| Stage | Calls | Exclusive ms | % of service call |\n|---|---:|---:|---:|")
        acc = 0.0
        for k, (cnt, incl, excl) in req:
            if excl * 1000 < 1 and cnt < 2:
                continue
            acc += excl
            out.append(f"| {k.split('|', 1)[1]} | {cnt:.0f} | {excl*1000:.0f} | {100*excl/svc:.1f}% |" if svc else
                       f"| {k.split('|', 1)[1]} | {cnt:.0f} | {excl*1000:.0f} | n/a |")
        if svc:
            out.append(f"| (everything else in the service call: queries, policy, bookkeeping) | | {(svc-acc)*1000:.0f} | {100*(svc-acc)/svc:.1f}% |")
        pool = [(k, v) for k, v in agg.items() if not k.startswith("request|") and not k.startswith("loop|")]
        pool.sort(key=lambda kv: -kv[1][1])
        if pool:
            out.append("\n**Other threads** (provider fan-out and deadline-runner pool; thread-seconds, run in parallel with the request thread):\n")
            out.append("| Thread kind | Operation | Calls | Inclusive ms (thread-s) | Mean ms/call |\n|---|---|---:|---:|---:|")
            for k, (cnt, incl, excl) in pool[:10]:
                kind, name = k.split("|", 1)
                out.append(f"| {kind} | {name} | {cnt:.0f} | {incl*1000:.0f} | {1000*incl/max(cnt,1):.2f} |")
    return "\n".join(out) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--providers", choices=("memory", "emulators"), default="memory")
    r.add_argument("--size-mib", type=float, default=100)
    r.add_argument("--chunk-mib", type=float, default=1)
    r.add_argument("--repeats", type=int, default=3)
    r.add_argument("--out")
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, required=True)
    s.add_argument("--data-dir", required=True)
    s.add_argument("--providers", required=True)
    s.add_argument("--chunk-bytes", type=int, required=True)
    s.add_argument("--max-upload", type=int, required=True)
    a = ap.parse_args()
    {"run": cmd_run, "serve": cmd_serve}[a.cmd](a)


if __name__ == "__main__":
    main()
