#!/usr/bin/env python3
"""Performance harness for the zero-trust chunked storage backend (Phase 0).

Measures, WITHOUT changing any application code:

  run     end-to-end upload and download time per file size through the full API
          stack (auth, policy, KMS, chunking, AES-256-GCM, R=2 placement with
          read-back verification, audit). Two transports:
            http        a real uvicorn server in its own process on loopback; the
                        client streams the upload from a file and the download to a
                        file (works at GB sizes; server peak RSS is recorded)
            testclient  in-process FastAPI TestClient (how the paper's Table was
                        measured; the body is built in memory, so use <= ~200 MiB)
          and two provider modes:
            memory      in-memory providers (no network, no provider latency)
            emulators   the real boto3 / azure-storage-blob / google-cloud-storage
                        adapters against moto / Azurite / gcp-storage-emulator
                        (scripts/emulators.sh start first)
  crypto  the cipher pipeline alone: split, encrypt (AES-256-GCM + SHA-256),
          decrypt (SHA-256 verify + GCM), next to raw AES-GCM and raw SHA-256
  report  render a results directory as a markdown table

Every timed repeat gets a FRESH server and empty providers, after an untimed
1 MiB warm-up upload and download, so repeats are independent and memory
providers do not accumulate data.

Run from the backend directory with the project venv, e.g.

  cd backend
  .venv/bin/python ../scripts/bench/bench.py run --sizes 5,20,100 --repeats 5
  .venv/bin/python ../scripts/bench/bench.py crypto --sizes 5,20,100,200,1024
  .venv/bin/python ../scripts/bench/bench.py report ../scripts/bench/results/<dir>

Benchmark-only settings (config values, not code): rate limits and the bulk
download detector are raised so repeated transfers are not throttled or blocked,
env=test is used (as in the test harness) and require_mfa_for_login=False, so a
password session can reach the file routes. Authentication is outside the timed
sections. The Argon2 hasher is made cheap for the same reason.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import resource
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
BACKEND = REPO / "backend"
sys.path.insert(0, str(BACKEND))

MIB = 1024 * 1024
PASSWORD = "Correct-Horse-Battery-42"
ADMIN_PASSWORD = "Admin-Horse-Battery-4242"
EMU_ENV = REPO / "scripts" / ".emulators" / "run" / "emulators.env"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def settings_kwargs(data_dir: Path, chunk_bytes: int, max_upload: int, providers: str) -> dict:
    cfg = dict(
        env="test", data_dir=data_dir, cookie_secure=False,
        chunk_size_bytes=chunk_bytes, max_upload_bytes=max_upload,
        require_mfa_for_login=False,
        bootstrap_admin_username="root", bootstrap_admin_password=ADMIN_PASSWORD,
        rate_limit_login_per_minute=10**6, rate_limit_register_per_minute=10**6,
        rate_limit_upload_per_minute=10**6, rate_limit_download_per_minute=10**6,
        rate_limit_verify_per_minute=10**6, rate_limit_audit_export_per_minute=10**6,
        rate_limit_invalid_token_per_minute=10**6,
        detect_max_downloads_in_window=10**6, detect_max_download_bytes_in_window=2**50,
        storage_timeout_seconds=600.0,
    )
    if providers == "memory":
        cfg["storage_providers"] = "memory-a,memory-b,memory-c"
    return cfg


def cheap_hasher():
    from app.auth import PasswordHasher
    return PasswordHasher(time_cost=1, memory_cost_kib=8, parallelism=1)


def read_emulator_env() -> dict[str, str]:
    if not EMU_ENV.exists():
        sys.exit(f"{EMU_ENV} not found: run scripts/emulators.sh start first")
    out = {}
    for line in EMU_ENV.read_text().splitlines():
        m = re.match(r'export (\w+)="(.*)"\s*$', line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def vm_hwm_mib(pid: int) -> float | None:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) / 1024
    except OSError:
        return None
    return None


def self_peak_rss_mib() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # Linux: KiB


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while blk := f.read(4 * MIB):
            h.update(blk)
    return h.hexdigest()


def make_payload(path: Path, size: int) -> None:
    with open(path, "wb") as f:
        left = size
        while left > 0:
            n = min(left, 8 * MIB)
            f.write(os.urandom(n))
            left -= n


def environment_info() -> dict:
    def sh(*cmd):
        try:
            return subprocess.check_output(cmd, text=True, cwd=REPO, stderr=subprocess.DEVNULL).strip()
        except Exception:
            return None
    cpu = None
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    mem = None
    try:
        mem = int(Path("/proc/meminfo").read_text().split()[1]) // 1024
    except OSError:
        pass
    import cryptography
    import fastapi
    import uvicorn
    return dict(
        timestamp=datetime.now().astimezone().isoformat(timespec="seconds"),
        git_commit=sh("git", "rev-parse", "--short", "HEAD"),
        git_dirty=bool(sh("git", "status", "--porcelain", "--", "backend/app")),
        python=platform.python_version(), platform=platform.platform(),
        cpu=cpu, logical_cpus=os.cpu_count(), mem_total_mib=mem,
        cryptography=cryptography.__version__, fastapi=fastapi.__version__, uvicorn=uvicorn.__version__,
        **machine_state(),
    )


def machine_state() -> dict:
    """Load, free memory and free disk when the run starts, to help explain drift between sessions."""
    out: dict = {}
    try:
        out["loadavg_1m"] = round(os.getloadavg()[0], 2)
    except OSError:
        pass
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                out["mem_available_mib"] = int(line.split()[1]) // 1024
                break
    except OSError:
        pass
    try:
        out["disk_free_gib_tmp"] = round(shutil.disk_usage(tempfile.gettempdir()).free / 2**30)
    except OSError:
        pass
    return out


def summarize(xs: list[float]) -> dict:
    xs = sorted(xs)
    if not xs:
        return {}
    p95 = xs[min(len(xs) - 1, int(round(0.95 * (len(xs) - 1))))]
    return dict(n=len(xs), min=xs[0], median=statistics.median(xs), max=xs[-1], p95=p95,
                mean=statistics.fmean(xs), stdev=statistics.stdev(xs) if len(xs) > 1 else 0.0)


# --------------------------------------------------------------------------- #
# internal: server process
# --------------------------------------------------------------------------- #
def cmd_serve(a) -> None:
    import uvicorn

    from app.config import Settings
    from app.main import create_app
    cfg = settings_kwargs(Path(a.data_dir), a.chunk_bytes, a.max_upload, a.providers)
    settings = Settings(_env_file=None, **cfg)
    providers = None
    if a.providers == "memory":
        from app.storage.memory import MemoryProvider
        providers = {n: MemoryProvider(n) for n in settings.provider_names}
    app = create_app(settings, providers=providers, password_hasher=cheap_hasher())
    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning", access_log=False)


# --------------------------------------------------------------------------- #
# internal: a private emulator trio (own ports, temp data dirs, torn down after)
# --------------------------------------------------------------------------- #
class ManagedEmulators:
    """moto (S3), Azurite (Azure Blob) and gcp-storage-emulator (GCS), started on free
    ports with temporary data directories. Independent of scripts/emulators.sh, so a
    developer's running emulators and their data are never touched or wiped."""

    def __init__(self) -> None:
        self.dir: Path | None = None
        self.procs: list[subprocess.Popen] = []

    def start(self, attempts: int = 3) -> dict[str, str]:
        """Start the trio, retrying with fresh ports and a fresh data directory if an
        emulator is not ready in time or bucket setup fails (seen once in about 100
        starts: moto answered the port but returned 501 to the first bucket request)."""
        last: Exception | None = None
        for n in range(1, attempts + 1):
            try:
                return self._start_once()
            except Exception as exc:        # _start_once has already torn everything down
                last = exc
                print(f"[bench] emulator start failed (attempt {n}/{attempts}): {str(exc).strip()[:240]}",
                      file=sys.stderr, flush=True)
                time.sleep(1.0)
        raise RuntimeError(f"emulators did not start after {attempts} attempts: {last}")

    def _start_once(self) -> dict[str, str]:
        self.dir = Path(tempfile.mkdtemp(prefix="zt-bench-emu-"))
        host = "127.0.0.1"
        s3, az, gcs = free_port(), free_port(), free_port()
        venv = BACKEND / ".venv" / "bin"
        penv = dict(os.environ)
        node_bin = Path.home() / ".local" / "node" / "bin"
        if node_bin.exists():
            penv["PATH"] = f"{node_bin}{os.pathsep}{penv.get('PATH', '')}"
        cmds = [
            [str(venv / "moto_server"), "-H", host, "-p", str(s3)],
            [str(REPO / "scripts/.emulators/node_modules/.bin/azurite-blob"), "--blobHost", host, "--blobPort",
             str(az), "--location", str(self.dir / "azurite"), "--skipApiVersionCheck", "--disableTelemetry", "--silent"],
            [str(venv / "gcp-storage-emulator"), "--data-dir", str(self.dir / "gcs"), "start", "--host", host,
             "--port", str(gcs)],
        ]
        (self.dir / "azurite").mkdir()
        (self.dir / "gcs").mkdir()
        try:
            for c in cmds:
                self.procs.append(subprocess.Popen(c, env=penv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                                   start_new_session=True))
            for port in (s3, az, gcs):
                for _ in range(300):
                    try:
                        socket.create_connection((host, port), timeout=0.2).close()
                        break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise RuntimeError(f"emulator on port {port} did not start")
            azure_key = ("Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==")
            env = {
                "ZT_STORAGE_PROVIDERS": "aws-s3,azure-blob,gcs",
                "ZT_S3_ENDPOINT_URL": f"http://{host}:{s3}", "ZT_S3_REGION": "us-east-1", "ZT_S3_BUCKET": "zt-chunks",
                "ZT_S3_ACCESS_KEY_ID": "test", "ZT_S3_SECRET_ACCESS_KEY": "test",
                "ZT_AZURE_CONNECTION_STRING": ("DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;"
                                               f"AccountKey={azure_key};BlobEndpoint=http://{host}:{az}/devstoreaccount1;"),
                "ZT_AZURE_CONTAINER": "zt-chunks",
                "ZT_GCS_ENDPOINT_URL": f"http://{host}:{gcs}", "ZT_GCS_PROJECT": "zt-local", "ZT_GCS_BUCKET": "zt-chunks",
            }
            r = subprocess.run([sys.executable, str(REPO / "scripts/emulators/ensure_buckets.py")],
                               env={**os.environ, **env}, capture_output=True, text=True)
            if r.returncode != 0:
                raise RuntimeError("bucket setup failed: " + (r.stderr or r.stdout)[-500:])
            return env
        except BaseException:
            self.stop()
            raise

    def stop(self) -> None:
        for p in self.procs:
            try:
                os.killpg(p.pid, 15)
            except (ProcessLookupError, PermissionError):
                pass
        for p in self.procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(p.pid, 9)
                except (ProcessLookupError, PermissionError):
                    pass
        self.procs = []
        if self.dir is not None:
            shutil.rmtree(self.dir, ignore_errors=True)
            self.dir = None


# --------------------------------------------------------------------------- #
# internal: one http repeat
# --------------------------------------------------------------------------- #
def http_repeat(size: int, chunk_bytes: int, providers: str, payload: Path, payload_sha: str,
                max_upload: int) -> dict:
    import httpx
    port = free_port()
    work = Path(tempfile.mkdtemp(prefix="zt-bench-"))
    env = dict(os.environ)
    emu = ManagedEmulators() if providers == "emulators" else None
    if emu is not None:
        env.update(emu.start())
    cmd =[sys.executable, str(Path(__file__).resolve()), "serve", "--port", str(port),
           "--data-dir", str(work / "data"), "--providers", providers,
           "--chunk-bytes", str(chunk_bytes), "--max-upload", str(max_upload)]
    srv = subprocess.Popen(cmd, env=env, cwd=BACKEND, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    base = f"http://127.0.0.1:{port}"
    try:
        c = httpx.Client(base_url=base, timeout=None)
        for _ in range(300):
            if srv.poll() is not None:
                raise RuntimeError("server exited: " + (srv.stderr.read().decode(errors="replace")[-800:]))
            try:
                if c.get("/api/health").status_code == 200:
                    break
            except httpx.TransportError:
                pass
            time.sleep(0.1)
        else:
            raise RuntimeError("server did not become healthy")

        r = c.post("/api/auth/register", json={"username": "benchuser", "password": PASSWORD})
        assert r.status_code == 202, r.text

        def token() -> dict:
            r = c.post("/api/auth/login", json={"username": "benchuser", "password": PASSWORD})
            assert r.status_code == 200, r.text
            return {"Authorization": "Bearer " + r.json()["access_token"]}

        def upload(path: Path, h: dict):
            with open(path, "rb") as f:
                return c.post("/api/files", headers=h, files={"file": ("bench.bin", f, "application/octet-stream")})

        # untimed warm-up (1 MiB) so imports, pools and caches are hot
        wu = work / "warm.bin"
        make_payload(wu, MIB)
        h = token()
        r = upload(wu, h)
        assert r.status_code == 201, r.text
        with c.stream("GET", f"/api/files/{r.json()['id']}/download", headers=h) as d:
            for _ in d.iter_bytes(MIB):
                pass

        h = token()
        t0 = time.perf_counter()
        r = upload(payload, h)
        t_up = time.perf_counter() - t0
        assert r.status_code == 201, f"upload failed {r.status_code} {r.text[:300]}"
        fid = r.json()["id"]

        h = token()
        out = work / "down.bin"
        t_first = None
        t0 = time.perf_counter()
        with c.stream("GET", f"/api/files/{fid}/download", headers=h) as d:
            assert d.status_code == 200, d.status_code
            with open(out, "wb") as f:
                for blk in d.iter_bytes(4 * MIB):
                    if t_first is None:
                        t_first = time.perf_counter() - t0
                    f.write(blk)
        t_down = time.perf_counter() - t0
        ok = out.stat().st_size == size and sha256_file(out) == payload_sha
        return dict(upload_s=t_up, download_s=t_down, download_ttfb_s=t_first, verified=ok,
                    server_peak_rss_mib=vm_hwm_mib(srv.pid))
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=20)
        except subprocess.TimeoutExpired:
            srv.kill()
        if emu is not None:
            emu.stop()
        shutil.rmtree(work, ignore_errors=True)


def testclient_repeat(size: int, chunk_bytes: int, providers: str, data: bytes, max_upload: int) -> dict:
    from fastapi.testclient import TestClient

    from app.config import Settings
    from app.main import create_app
    from app.storage.memory import MemoryProvider
    if providers != "memory":
        raise SystemExit("testclient transport supports --providers memory only")
    work = Path(tempfile.mkdtemp(prefix="zt-bench-"))
    try:
        cfg = settings_kwargs(work / "data", chunk_bytes, max_upload, providers)
        settings = Settings(_env_file=None, **cfg)
        prov = {n: MemoryProvider(n) for n in settings.provider_names}
        app = create_app(settings, providers=prov, password_hasher=cheap_hasher(), background=False)
        with TestClient(app, base_url="https://testserver", client=("198.51.100.7", 50000)) as c:
            assert c.post("/api/auth/register", json={"username": "benchuser", "password": PASSWORD}).status_code == 202

            def token() -> dict:
                r = c.post("/api/auth/login", json={"username": "benchuser", "password": PASSWORD})
                assert r.status_code == 200, r.text
                return {"Authorization": "Bearer " + r.json()["access_token"]}

            h = token()
            r = c.post("/api/files", headers=h, files={"file": ("w.bin", os.urandom(MIB), "application/octet-stream")})
            assert r.status_code == 201, r.text
            assert c.get(f"/api/files/{r.json()['id']}/download", headers=h).status_code == 200
            h = token()
            t0 = time.perf_counter()
            r = c.post("/api/files", headers=h, files={"file": ("bench.bin", data, "application/octet-stream")})
            t_up = time.perf_counter() - t0
            assert r.status_code == 201, f"upload failed {r.status_code} {r.text[:300]}"
            h = token()
            t0 = time.perf_counter()
            d = c.get(f"/api/files/{r.json()['id']}/download", headers=h)
            t_down = time.perf_counter() - t0
            ok = d.status_code == 200 and d.content == data
            return dict(upload_s=t_up, download_s=t_down, download_ttfb_s=None, verified=ok,
                        server_peak_rss_mib=None)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def cmd_worker(a) -> None:
    size = int(a.size_mib * MIB)
    chunk_bytes = int(a.chunk_mib * MIB)
    max_upload = size + 16 * MIB
    rows = []
    if a.transport == "http":
        tmp = Path(tempfile.mkdtemp(prefix="zt-bench-payload-"))
        try:
            payload = tmp / "payload.bin"
            make_payload(payload, size)
            sha = sha256_file(payload)
            for _ in range(a.repeats):
                rows.append(http_repeat(size, chunk_bytes, a.providers, payload, sha, max_upload))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    else:
        data = os.urandom(size)
        for _ in range(a.repeats):
            rows.append(testclient_repeat(size, chunk_bytes, a.providers, data, max_upload))
    print("RESULT " + json.dumps(dict(repeats=rows, client_peak_rss_mib=self_peak_rss_mib())))


# --------------------------------------------------------------------------- #
# run / crypto / report
# --------------------------------------------------------------------------- #
def out_dir(a, name: str) -> Path:
    d = Path(a.out) if a.out else HERE / "results" / f"{datetime.now():%Y%m%d-%H%M%S}-{name}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def cmd_run(a) -> None:
    sizes = [float(s) for s in a.sizes.split(",")]
    d = out_dir(a, f"{a.transport}-{a.providers}")
    result = dict(kind="run", env=environment_info(),
                  params=dict(transport=a.transport, providers=a.providers, chunk_mib=a.chunk_mib,
                              repeats=a.repeats, sizes_mib=sizes), sizes=[])
    for s in sizes:
        print(f"[bench] {a.transport}/{a.providers} {s:g} MiB x{a.repeats} ...", flush=True)
        limit_min = getattr(a, "timeout_min", 60)
        try:
            p = subprocess.run([sys.executable, str(Path(__file__).resolve()), "worker", "--transport", a.transport,
                                "--providers", a.providers, "--size-mib", str(s), "--chunk-mib", str(a.chunk_mib),
                                "--repeats", str(a.repeats)], cwd=BACKEND, capture_output=True, text=True,
                               timeout=limit_min * 60)
        except subprocess.TimeoutExpired:
            print(f"        timed out after {limit_min} min", file=sys.stderr)
            result["sizes"].append(dict(size_mib=s, error=f"timed out after {limit_min} min"))
            continue
        line = next((ln for ln in p.stdout.splitlines() if ln.startswith("RESULT ")), None)
        if p.returncode != 0 or line is None:
            print(p.stdout[-1500:], p.stderr[-1500:], file=sys.stderr)
            result["sizes"].append(dict(size_mib=s, error=f"worker failed (rc={p.returncode})"))
            continue
        w = json.loads(line[7:])
        reps = w["repeats"]
        up = [r["upload_s"] for r in reps]
        dn = [r["download_s"] for r in reps]
        ttfb = [r["download_ttfb_s"] for r in reps if r["download_ttfb_s"] is not None]
        srv = [r["server_peak_rss_mib"] for r in reps if r["server_peak_rss_mib"]]
        entry = dict(size_mib=s, repeats=reps, all_verified=all(r["verified"] for r in reps),
                     upload_s=summarize(up), download_s=summarize(dn), download_ttfb_s=summarize(ttfb),
                     upload_mib_s=summarize([s / x for x in up]), download_mib_s=summarize([s / x for x in dn]),
                     server_peak_rss_mib=max(srv) if srv else None, client_peak_rss_mib=w["client_peak_rss_mib"])
        result["sizes"].append(entry)
        print(f"        upload median {entry['upload_s']['median']*1000:.0f} ms "
              f"({entry['upload_mib_s']['median']:.1f} MiB/s), download median "
              f"{entry['download_s']['median']*1000:.0f} ms ({entry['download_mib_s']['median']:.1f} MiB/s), "
              f"verified={entry['all_verified']}", flush=True)
    (d / "run.json").write_text(json.dumps(result, indent=1))
    (d / "run.md").write_text(render_run(result))
    print(f"[bench] wrote {d}")


def cmd_crypto(a) -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from app.cryptoengine.chunks import decrypt_chunk, encrypt_chunk, iter_plain_chunks
    from app.cryptoengine.keys import FileKeys
    d = out_dir(a, "crypto")
    chunk = int(a.chunk_mib * MIB)
    result = dict(kind="crypto", env=environment_info(), params=dict(chunk_mib=a.chunk_mib, repeats=a.repeats),
                  sizes=[])
    for s in [float(x) for x in a.sizes.split(",")]:
        size = int(s * MIB)
        print(f"[bench] crypto {s:g} MiB x{a.repeats} ...", flush=True)
        data = os.urandom(size)
        fid = "0" * 32
        keys = FileKeys.derive(os.urandom(32), fid)
        raw = AESGCM(os.urandom(32))
        reps = []
        for _ in range(a.repeats):
            t = time.perf_counter()
            chunks = list(iter_plain_chunks(io.BytesIO(data), chunk))
            t_split = time.perf_counter() - t
            t = time.perf_counter()
            enc = [encrypt_chunk(keys, fid, i, pt, fin) for i, pt, fin in chunks]
            t_enc = time.perf_counter() - t
            t = time.perf_counter()
            for (i, _pt, fin), e in zip(chunks, enc):
                decrypt_chunk(keys, fid, i, e.blob, fin, e.sha256_hex)
            t_dec = time.perf_counter() - t
            nonce = os.urandom(12)
            t = time.perf_counter()
            for _i, pt, _fin in chunks:
                raw.encrypt(nonce, pt, None)
            t_raw = time.perf_counter() - t
            t = time.perf_counter()
            hashlib.sha256(data).hexdigest()
            t_sha = time.perf_counter() - t
            reps.append(dict(split_s=t_split, encrypt_s=t_enc, decrypt_s=t_dec, raw_aesgcm_s=t_raw, raw_sha256_s=t_sha))
            del chunks, enc
        entry = dict(size_mib=s, chunks=-(-size // chunk), repeats=reps)
        for k in ("split_s", "encrypt_s", "decrypt_s", "raw_aesgcm_s", "raw_sha256_s"):
            entry[k] = summarize([r[k] for r in reps])
            entry[k[:-2] + "_mib_s"] = summarize([s / r[k] for r in reps])
        result["sizes"].append(entry)
        print(f"        encrypt {entry['encrypt_mib_s']['median']:.0f} MiB/s, decrypt "
              f"{entry['decrypt_mib_s']['median']:.0f} MiB/s, raw AES-GCM {entry['raw_aesgcm_mib_s']['median']:.0f} MiB/s, "
              f"raw SHA-256 {entry['raw_sha256_mib_s']['median']:.0f} MiB/s", flush=True)
        del data
    (d / "crypto.json").write_text(json.dumps(result, indent=1))
    (d / "crypto.md").write_text(render_crypto(result))
    print(f"[bench] wrote {d}")


def _rng(x: dict, scale: float = 1.0, fmt: str = "{:.0f}") -> str:
    return f"{fmt.format(x['median']*scale)} [{fmt.format(x['min']*scale)}-{fmt.format(x['max']*scale)}]"


def _env_lines(env: dict) -> str:
    return (f"- Machine: {env['cpu']}, {env['logical_cpus']} logical CPUs, {env['mem_total_mib']} MiB RAM\n"
            f"- Software: Python {env['python']}, cryptography {env['cryptography']}, FastAPI {env['fastapi']}, "
            f"uvicorn {env['uvicorn']}\n- Platform: {env['platform']}\n"
            f"- Commit: {env['git_commit']}{' (backend/app has uncommitted changes)' if env['git_dirty'] else ''}; "
            f"run at {env['timestamp']}\n")


def render_run(r: dict) -> str:
    p = r["params"]
    out = [f"# End-to-end upload/download ({p['transport']}, {p['providers']} providers)\n",
           f"Chunk size {p['chunk_mib']:g} MiB, replication as configured (R=2 of 3), {p['repeats']} repeats per size, "
           "fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.\n",
           _env_lines(r["env"]),
           "| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |",
           "|---:|---:|---:|---:|---:|---:|---:|:--:|"]
    for e in r["sizes"]:
        if "error" in e:
            out.append(f"| {e['size_mib']:g} | {e['error']} | | | | | | |")
            continue
        ttfb = _rng(e["download_ttfb_s"], 1000) if e["download_ttfb_s"] else "n/a"
        rss = f"{e['server_peak_rss_mib']:.0f}" if e["server_peak_rss_mib"] else "n/a"
        out.append(f"| {e['size_mib']:g} | {_rng(e['upload_s'], 1000)} | {_rng(e['upload_mib_s'], 1, '{:.1f}')} | "
                   f"{_rng(e['download_s'], 1000)} | {_rng(e['download_mib_s'], 1, '{:.1f}')} | {ttfb} | {rss} | "
                   f"{'yes' if e['all_verified'] else 'NO'} |")
    return "\n".join(out) + "\n"


def render_crypto(r: dict) -> str:
    out = [f"# Cipher pipeline alone (chunk {r['params']['chunk_mib']:g} MiB)\n",
           f"{r['params']['repeats']} repeats, single thread, data in memory, no I/O. Cells are `median [min-max]` in MiB/s. "
           "`encrypt` = AES-256-GCM with AAD + SHA-256 of the blob; `decrypt` = SHA-256 check + GCM verify.\n",
           _env_lines(r["env"]),
           "| Size (MiB) | Chunks | Split | Encrypt | Decrypt | Raw AES-GCM | Raw SHA-256 |",
           "|---:|---:|---:|---:|---:|---:|---:|"]
    for e in r["sizes"]:
        out.append(f"| {e['size_mib']:g} | {e['chunks']} | {_rng(e['split_mib_s'])} | {_rng(e['encrypt_mib_s'])} | "
                   f"{_rng(e['decrypt_mib_s'])} | {_rng(e['raw_aesgcm_mib_s'])} | {_rng(e['raw_sha256_mib_s'])} |")
    return "\n".join(out) + "\n"


def cmd_report(a) -> None:
    d = Path(a.dir)
    for name, fn in (("run.json", render_run), ("crypto.json", render_crypto)):
        if (d / name).exists():
            print(fn(json.loads((d / name).read_text())))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--sizes", default="5,20,100")
    r.add_argument("--repeats", type=int, default=5)
    r.add_argument("--transport", choices=("http", "testclient"), default="http")
    r.add_argument("--providers", choices=("memory", "emulators"), default="memory")
    r.add_argument("--chunk-mib", type=float, default=1)
    r.add_argument("--timeout-min", type=float, default=60, help="give up on one size after this many minutes")
    r.add_argument("--out")
    c = sub.add_parser("crypto")
    c.add_argument("--sizes", default="5,20,100,200")
    c.add_argument("--repeats", type=int, default=5)
    c.add_argument("--chunk-mib", type=float, default=1)
    c.add_argument("--out")
    rp = sub.add_parser("report")
    rp.add_argument("dir")
    w = sub.add_parser("worker")
    w.add_argument("--transport", required=True)
    w.add_argument("--providers", required=True)
    w.add_argument("--size-mib", type=float, required=True)
    w.add_argument("--chunk-mib", type=float, required=True)
    w.add_argument("--repeats", type=int, required=True)
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, required=True)
    s.add_argument("--data-dir", required=True)
    s.add_argument("--providers", required=True)
    s.add_argument("--chunk-bytes", type=int, required=True)
    s.add_argument("--max-upload", type=int, required=True)
    a = ap.parse_args()
    {"run": cmd_run, "crypto": cmd_crypto, "report": cmd_report, "worker": cmd_worker, "serve": cmd_serve}[a.cmd](a)


if __name__ == "__main__":
    main()
