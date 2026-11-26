#!/usr/bin/env python3
"""Measurement collectors for the statistical analysis (experiments a to h). Writes raw CSVs to analysis/data/.

Needs the three emulators running through scripts/emulators.sh (experiment d stops and restarts them):

  scripts/emulators.sh start
  backend/.venv/bin/python analysis/collect.py --only a,b,c,d,e,f,g --n 30

Each API measurement is one HTTP request to a real uvicorn server on loopback (full stack: auth, policy, KMS, chunking,
AES-256-GCM, replication to 2 of 3 emulators with read-back verification, audit). Conditions are interleaved in a random order
(seeded) so slow or fast periods of the machine affect them alike; every condition gets warm-up repetitions that are discarded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import DATA, MIB, REPO, SEED, env_info, entropy_bits, st  # noqa: E402

sys.path.insert(0, str(REPO / "scripts" / "bench"))
import bench  # noqa: E402

EMU = REPO / "scripts" / "emulators.sh"
PROV = ("aws-s3", "azure-blob", "gcs")


def shell_env() -> dict:
    env = dict(os.environ)
    node = Path.home() / ".local" / "node" / "bin"
    if node.exists():
        env["PATH"] = f"{node}{os.pathsep}{env['PATH']}"
    return env


def emulators(*args):
    return subprocess.run(["bash", str(EMU), *args], capture_output=True, text=True, env=shell_env())


def need_emulators() -> None:
    out = emulators("status").stdout
    if out.count(" running ") != 3:
        sys.exit("The three emulators must be running (scripts/emulators.sh start). Status:\n" + out)


def save(name: str, rows: list[dict]) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(DATA / f"{name}.csv", index=False)
    print(f"[collect] wrote data/{name}.csv ({len(rows)} rows)", flush=True)


def make_file(tmp: Path, size_mib: float, name: str | None = None) -> tuple[Path, str]:
    p = tmp / (name or f"p{size_mib:g}.bin")
    bench.make_payload(p, int(size_mib * MIB))
    return p, bench.sha256_file(p)


# --------------------------------------------------------------------------- #
# a real API server over the emulators
# --------------------------------------------------------------------------- #
class Stack:
    def __init__(self, label: str, chunk_bytes: int, env_extra: dict | None = None, max_upload: int = 128 * MIB):
        import httpx
        self.label = label
        self.work = Path(tempfile.mkdtemp(prefix=f"zt-an-{label}-"))
        self.port = bench.free_port()
        env = {**os.environ, **bench.read_emulator_env(), **(env_extra or {})}
        self.log = open(self.work / "server.log", "wb")              # a file, not a pipe: an unread pipe fills up and blocks the server
        self.proc = subprocess.Popen(
            [sys.executable, str(REPO / "scripts/bench/bench.py"), "serve", "--port", str(self.port), "--data-dir", str(self.work / "data"),
             "--providers", "emulators", "--chunk-bytes", str(chunk_bytes), "--max-upload", str(max_upload)],
            env=env, cwd=REPO / "backend", stdout=subprocess.DEVNULL, stderr=self.log)
        self.c = httpx.Client(base_url=f"http://127.0.0.1:{self.port}", timeout=httpx.Timeout(600.0))   # a stall becomes a failed trial, not an endless wait
        for _ in range(600):
            if self.proc.poll() is not None:
                raise RuntimeError("server exited: " + (self.work / "server.log").read_text(errors="replace")[-500:])
            try:
                if self.c.get("/api/health").status_code == 200:
                    break
            except httpx.TransportError:
                pass
            time.sleep(0.1)
        r = self.c.post("/api/auth/register", json={"username": "analyst", "password": bench.PASSWORD})
        assert r.status_code == 202, r.text

    def headers(self) -> dict:
        r = self.c.post("/api/auth/login", json={"username": "analyst", "password": bench.PASSWORD})
        return {"Authorization": "Bearer " + r.json()["access_token"]}

    def upload(self, path: Path):
        h = self.headers()
        t0 = time.perf_counter()
        try:
            with open(path, "rb") as f:
                r = self.c.post("/api/files", headers=h, files={"file": ("a.bin", f, "application/octet-stream")})
            return time.perf_counter() - t0, (r.json().get("id") if r.status_code == 201 else None), r.status_code
        except Exception as exc:                                    # a connection error is a failed trial, not a crash
            return time.perf_counter() - t0, None, f"error:{type(exc).__name__}"

    def download(self, fid: str, out: Path):
        h = self.headers()
        t0 = time.perf_counter()
        try:
            with self.c.stream("GET", f"/api/files/{fid}/download", headers=h) as d:
                code = d.status_code
                if code == 200:
                    with open(out, "wb") as f:
                        for blk in d.iter_bytes(4 * MIB):
                            f.write(blk)
                else:
                    d.read()
            return time.perf_counter() - t0, code
        except Exception as exc:
            return time.perf_counter() - t0, f"error:{type(exc).__name__}"

    def db(self) -> sqlite3.Connection:
        return sqlite3.connect(f"file:{self.work / 'data' / 'metadata.db'}?mode=ro", uri=True)

    def close(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()
        shutil.rmtree(self.work, ignore_errors=True)


def intact(out: Path, size: int, sha: str) -> bool:
    return out.exists() and out.stat().st_size == size and bench.sha256_file(out) == sha


def providers_direct():
    """The application's own provider adapters, for the plain baseline and for reading raw stored objects."""
    os.environ.update(bench.read_emulator_env())
    from app.config import Settings
    from app.storage import build_providers
    s = Settings(_env_file=None, env="test", data_dir=Path(tempfile.gettempdir()) / f"zt-an-cfg-{uuid.uuid4().hex}",
                 storage_providers=",".join(PROV), storage_timeout_seconds=120.0)
    return build_providers(s)


# --------------------------------------------------------------------------- #
# a. latency and throughput against file size
# --------------------------------------------------------------------------- #
def exp_a(n: int, warm: int = 3, sizes=(1, 4, 16, 64)) -> None:
    rng, tmp, rows = random.Random(SEED), Path(tempfile.mkdtemp(prefix="zt-an-a-")), []
    files = {s: make_file(tmp, s) for s in sizes}
    stack = Stack("a", MIB)
    try:
        for r in range(-warm, n):
            order = list(sizes)
            rng.shuffle(order)
            for s in order:
                path, sha = files[s]
                up, fid, code = stack.upload(path)
                ok_up = fid is not None
                if ok_up:
                    out = tmp / "dl.bin"
                    dn, dcode = stack.download(fid, out)
                    ok_dn = dcode == 200 and intact(out, int(s * MIB), sha)
                if r >= 0:
                    rows.append(dict(size_mib=s, rep=r, op="upload", seconds=up, ok=ok_up, status=code))
                    if ok_up:
                        rows.append(dict(size_mib=s, rep=r, op="download", seconds=dn, ok=ok_dn, status=dcode))
            print(f"[a] rep {r + 1 if r >= 0 else r}/{n}", flush=True) if r % 10 == 9 or r < 0 else None
    finally:
        stack.close()
        shutil.rmtree(tmp, ignore_errors=True)
    save("a_scaling", rows)


# --------------------------------------------------------------------------- #
# b. cost of security: the same bytes with and without the security pipeline
# --------------------------------------------------------------------------- #
def plain_chunked_up(provs, data: bytes, chunk: int, pool, rng) -> tuple[float, list]:
    names, off, manifest = list(PROV), rng.randrange(3), []
    t0 = time.perf_counter()
    for i, pos in enumerate(range(0, len(data), chunk)):
        blob = data[pos:pos + chunk]
        key = "an-plain-" + uuid.uuid4().hex
        a, b = names[(i + off) % 3], names[(i + off + 1) % 3]
        for f in [pool.submit(provs[a].put, key, blob), pool.submit(provs[b].put, key, blob)]:
            f.result()
        manifest.append((key, a, b))
    return time.perf_counter() - t0, manifest


def plain_chunked_down(provs, manifest) -> tuple[float, bytes]:
    t0 = time.perf_counter()
    data = b"".join(provs[a].get(key) for key, a, _ in manifest)
    return time.perf_counter() - t0, data


def exp_b(n: int, warm: int = 3, sizes=(4, 16, 64)) -> None:
    rng, tmp, rows = random.Random(SEED + 1), Path(tempfile.mkdtemp(prefix="zt-an-b-")), []
    files = {s: make_file(tmp, s) for s in sizes}
    stack, provs = Stack("b", MIB), providers_direct()
    pool = ThreadPoolExecutor(max_workers=2)
    try:
        for r in range(-warm, n):
            cells = [(s, arm) for s in sizes for arm in ("app", "plain_chunked", "plain_single")]
            rng.shuffle(cells)
            for s, arm in cells:
                path, sha = files[s]
                size = int(s * MIB)
                if arm == "app":
                    up, fid, code = stack.upload(path)
                    ok_up = fid is not None
                    out = tmp / "dl.bin"
                    dn, dcode = stack.download(fid, out) if ok_up else (float("nan"), "n/a")
                    ok_dn = ok_up and dcode == 200 and intact(out, size, sha)
                else:
                    data = path.read_bytes()
                    if arm == "plain_chunked":
                        up, manifest = plain_chunked_up(provs, data, MIB, pool, rng)
                        dn, back = plain_chunked_down(provs, manifest)
                        cleanup = [(provs[a], k) for k, a, b in manifest] + [(provs[b], k) for k, a, b in manifest]
                    else:
                        key = "an-single-" + uuid.uuid4().hex
                        t0 = time.perf_counter(); provs["aws-s3"].put(key, data); up = time.perf_counter() - t0
                        t0 = time.perf_counter(); back = provs["aws-s3"].get(key); dn = time.perf_counter() - t0
                        cleanup = [(provs["aws-s3"], key)]
                    ok_up = True
                    ok_dn = hashlib.sha256(back).hexdigest() == sha
                    for p_, k in cleanup:
                        p_.delete(k)
                if r >= 0:
                    rows.append(dict(arm=arm, size_mib=s, rep=r, op="upload", seconds=up, ok=ok_up))
                    rows.append(dict(arm=arm, size_mib=s, rep=r, op="download", seconds=dn, ok=ok_dn))
            if r % 10 == 9 or r < 0:
                print(f"[b] rep {r + 1 if r >= 0 else r}/{n}", flush=True)
    finally:
        pool.shutdown()
        stack.close()
        shutil.rmtree(tmp, ignore_errors=True)
    save("b_overhead", rows)

    # CPU cost of the cipher alone (per MiB), with no I/O: the same AEAD calls the application makes
    from app.cryptoengine.chunks import decrypt_chunk, encrypt_chunk
    from app.cryptoengine.keys import FileKeys
    fid = "0" * 32
    keys = FileKeys.derive(os.urandom(32), fid)
    blobs = [os.urandom(MIB) for _ in range(16)]
    micro = []
    for r in range(-warm, n):
        t0 = time.perf_counter()
        enc = [encrypt_chunk(keys, fid, i, b, i == 15) for i, b in enumerate(blobs)]
        te = (time.perf_counter() - t0) / 16
        t0 = time.perf_counter()
        for i, e in enumerate(enc):
            decrypt_chunk(keys, fid, i, e.blob, i == 15, e.sha256_hex)
        td = (time.perf_counter() - t0) / 16
        if r >= 0:
            micro += [dict(rep=r, op="encrypt", seconds_per_mib=te), dict(rep=r, op="decrypt", seconds_per_mib=td)]
    save("b_crypto_micro", micro)


# --------------------------------------------------------------------------- #
# c. chunk size
# --------------------------------------------------------------------------- #
def exp_c(n: int, warm: int = 3, chunks=(256 * 1024, MIB, 4 * MIB, 16 * MIB), size_mib: int = 32) -> None:
    rng, tmp, rows = random.Random(SEED + 2), Path(tempfile.mkdtemp(prefix="zt-an-c-")), []
    path, sha = make_file(tmp, size_mib)
    stacks = {c: Stack(f"c{c // 1024}k", c) for c in chunks}
    try:
        for r in range(-warm, n):
            order = list(chunks)
            rng.shuffle(order)
            for c in order:
                up, fid, code = stacks[c].upload(path)
                out = tmp / "dl.bin"
                dn, dcode = stacks[c].download(fid, out) if fid else (float("nan"), "n/a")
                ok_dn = fid is not None and dcode == 200 and intact(out, size_mib * MIB, sha)
                if r >= 0:
                    rows.append(dict(chunk_kib=c // 1024, rep=r, op="upload", seconds=up, ok=fid is not None))
                    rows.append(dict(chunk_kib=c // 1024, rep=r, op="download", seconds=dn, ok=ok_dn))
            if r % 10 == 9 or r < 0:
                print(f"[c] rep {r + 1 if r >= 0 else r}/{n}", flush=True)
    finally:
        for s in stacks.values():
            s.close()
        shutil.rmtree(tmp, ignore_errors=True)
    save("c_chunk", rows)


# --------------------------------------------------------------------------- #
# d. fault tolerance: a real emulator outage
# --------------------------------------------------------------------------- #
def exp_d(n: int, trials: int, warm: int = 3) -> None:
    tmp, rows = Path(tempfile.mkdtemp(prefix="zt-an-d-")), []
    big, big_sha = make_file(tmp, 16, "d16.bin")
    small, small_sha = make_file(tmp, 4, "d4.bin")
    stack = Stack("d", MIB)
    out = tmp / "dl.bin"

    def dl(phase, i, fid, path=big, sha=big_sha, size=16):
        dn, code = stack.download(fid, out)
        ok = code == 200 and intact(out, size * MIB, sha)
        rows.append(dict(phase=phase, trial=i, op="download", seconds=dn, ok=ok, status=code))
        return ok

    try:
        up, fid, code = stack.upload(big)
        assert fid, f"setup upload failed: {code}"
        for i in range(-warm, n):                                       # all providers up
            ok = dl("all_up", i, fid)
            if i < 0:
                rows.pop()
        print("[d] all_up done", flush=True)

        emulators("stop-one", "gcs")                                     # a real outage: the gcs emulator process is killed
        time.sleep(1.0)
        for i in range(trials):                                         # one provider down: reads
            dl("gcs_down", i, fid)
        print("[d] gcs_down downloads done", flush=True)
        up_ids = []
        for i in range(trials):                                         # one provider down: writes (placement failover)
            upt, f2, code = stack.upload(small)
            rows.append(dict(phase="gcs_down", trial=i, op="upload", seconds=upt, ok=f2 is not None, status=code))
            if f2:
                up_ids.append(f2)
        q = ",".join(f"'{x}'" for x in up_ids) or "''"
        replicas = dict(stack.db().execute(
            f"select r.provider, count(*) from chunk_replicas r join chunks c on c.id = r.chunk_id where c.file_id in ({q}) and r.status='stored' group by r.provider").fetchall())
        rows.append(dict(phase="gcs_down", trial=-1, op="replicas_on_gcs_for_uploads_during_outage", seconds=float("nan"),
                         ok=replicas.get("gcs", 0) == 0, status=json.dumps(replicas)))
        print("[d] gcs_down uploads done", flush=True)

        emulators("stop-one", "azure")                                   # two providers down: beyond the R=2 design limit
        time.sleep(1.0)
        for i in range(10):
            dl("two_down", i, fid)
        print("[d] two_down done", flush=True)
    finally:
        emulators("start-one", "azure")
        emulators("start-one", "gcs")
    t0 = time.time()
    recovered = False
    while time.time() - t0 < 120 and not recovered:                     # breaker and health monitor need time to notice
        recovered = dl("recovery_probe", int(time.time() - t0), fid)
        time.sleep(2)
    rows.append(dict(phase="recovery", trial=0, op="time_to_first_good_download", seconds=time.time() - t0, ok=recovered, status=""))
    for i in range(5):
        dl("restored", i, fid)
    stack.close()
    shutil.rmtree(tmp, ignore_errors=True)
    save("d_fault", rows)


# --------------------------------------------------------------------------- #
# e. placement balance
# --------------------------------------------------------------------------- #
def exp_e(files_n: int) -> None:
    tmp, rows = Path(tempfile.mkdtemp(prefix="zt-an-e-")), []
    path, _ = make_file(tmp, 8)
    for strategy in ("rotating", "hash"):
        stack = Stack(f"e-{strategy}", MIB, env_extra={"ZT_PLACEMENT_STRATEGY": strategy})
        try:
            for i in range(files_n):
                _, fid, code = stack.upload(path)
                assert fid, code
            counts = dict(stack.db().execute("select provider, count(*) from chunk_replicas where status='stored' group by provider").fetchall())
            pair_rows = stack.db().execute("select chunk_id, provider from chunk_replicas where status='stored'").fetchall()
            pairs: dict = {}
            for cid, prov in pair_rows:
                pairs.setdefault(cid, []).append(prov)
            pair_counts: dict = {}
            for cid, ps in pairs.items():
                key = "+".join(sorted(ps))
                pair_counts[key] = pair_counts.get(key, 0) + 1
            for prov in PROV:
                rows.append(dict(strategy=strategy, kind="replicas_per_provider", label=prov, count=counts.get(prov, 0)))
            for key, c in sorted(pair_counts.items()):
                rows.append(dict(strategy=strategy, kind="provider_pair_per_chunk", label=key, count=c))
            print(f"[e] {strategy}: replicas {counts}", flush=True)
        finally:
            stack.close()
    shutil.rmtree(tmp, ignore_errors=True)
    save("e_placement", rows)


# --------------------------------------------------------------------------- #
# f. ciphertext randomness, read raw from the emulators
# --------------------------------------------------------------------------- #
def exp_f() -> None:
    tmp, rows = Path(tempfile.mkdtemp(prefix="zt-an-f-")), []
    sentence = (b"The quick brown fox jumps over the lazy dog while the zero trust storage framework "
                b"encrypts every chunk before it leaves the backend. ")
    kinds = {"random": os.urandom(16 * MIB), "english_text": (sentence * (16 * MIB // len(sentence) + 1))[:16 * MIB],
             "zeros": bytes(16 * MIB)}
    provs = providers_direct()
    stack = Stack("f", MIB)
    try:
        for kind, plain in kinds.items():
            p = tmp / f"{kind}.bin"
            p.write_bytes(plain)
            _, fid, code = stack.upload(p)
            assert fid, code
            chunks = stack.db().execute("select id, \"index\" from chunks where file_id=? order by \"index\"", (fid,)).fetchall()
            reps = {}
            for cid, prov in stack.db().execute("select chunk_id, provider from chunk_replicas where status='stored'").fetchall():
                reps.setdefault(cid, []).append(prov)
            for cid, idx in chunks:
                pe = entropy_bits(plain[idx * MIB:(idx + 1) * MIB])
                for prov in reps[cid]:
                    blob = provs[prov].get(cid)                         # the raw object exactly as the provider holds it
                    counts = np.bincount(np.frombuffer(blob, dtype=np.uint8), minlength=256)
                    chi = st.chisquare(counts)
                    rows.append(dict(kind=kind, chunk_index=idx, provider=prov, object_bytes=len(blob),
                                     entropy_cipher=entropy_bits(blob), entropy_plain=pe, chi2=float(chi.statistic), p=float(chi.pvalue)))
            print(f"[f] {kind}: {len(chunks)} chunks read raw", flush=True)
    finally:
        stack.close()
        shutil.rmtree(tmp, ignore_errors=True)
    save("f_entropy", rows)


# --------------------------------------------------------------------------- #
# g. audit log: verify_chain scaling and record() throughput
# --------------------------------------------------------------------------- #
def exp_g(counts, reps: int) -> None:
    from app.config import Settings
    from app.main import create_app
    from app.storage.memory import MemoryProvider
    work = Path(tempfile.mkdtemp(prefix="zt-an-g-"))
    settings = Settings(_env_file=None, **bench.settings_kwargs(work / "data", MIB, 128 * MIB, "memory"))
    app = create_app(settings, providers={n: MemoryProvider(n) for n in settings.provider_names}, background=False,
                     password_hasher=bench.cheap_hasher())
    audit = app.state.container.audit
    verify_rows, record_rows, done = [], [], 0
    try:
        for target in counts:
            while done < target:
                block = min(1000, target - done)
                t0 = time.perf_counter()
                for i in range(block):
                    audit.record(event_type="analysis.event", action="file:read", outcome="success", actor_id="u_analysis",
                                 resource_type="file", resource_id=f"f{done + i}", details={"chunk_index": (done + i) % 8})
                dt = time.perf_counter() - t0
                done += block
                record_rows.append(dict(events_total=done, block=block, seconds=dt, events_per_s=block / dt))
            total = audit.search(limit=1)[1]
            assert audit.verify_chain().ok
            for r in range(reps):
                t0 = time.perf_counter()
                rep = audit.verify_chain()
                verify_rows.append(dict(events=total, rep=r, seconds=time.perf_counter() - t0, ok=bool(rep.ok)))
            print(f"[g] {total} events: verify median {np.median([v['seconds'] for v in verify_rows if v['events'] == total]):.3f} s", flush=True)
    finally:
        audit.close()
        shutil.rmtree(work, ignore_errors=True)
    save("g_audit_verify", verify_rows)
    save("g_audit_record", record_rows)


# --------------------------------------------------------------------------- #
# h. attack outcomes, parsed from the output of scripts/attacks/run_all.sh --markdown
# --------------------------------------------------------------------------- #
ROW = re.compile(r"^\| ((?:S|E)\d+) \| (.*?) \| (.*?) \| (.*?) \| (.*?) \| (PASS|FAIL|XFAIL|XPASS|SKIP\w*|ERROR) \| `?(.*?)`? \|$")


def exp_h(path: Path) -> None:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        m = ROW.match(line)
        if m:
            rows.append(dict(scenario=m[1], attempt=m[2], mechanism=m[3], observed=m[4], audit=m[5], outcome=m[6], test=m[7]))
    assert rows, f"no scenario rows found in {path}"
    save("h_attacks", rows)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", default="a,b,c,d,e,f,g,h")
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--quick", action="store_true", help="tiny sample sizes, to test the pipeline")
    ap.add_argument("--attacks-file", default=str(DATA / "attacks_run.txt"))
    a = ap.parse_args()
    only = set(a.only.split(","))
    n = 4 if a.quick else a.n
    trials = 10 if a.quick else 100
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / "meta.json").write_text(json.dumps(dict(env=env_info(), n=n, trials=trials, quick=a.quick, only=sorted(only)), indent=1))
    if only & set("abcdef"):
        need_emulators()
    t00 = time.time()
    if "a" in only: exp_a(n)
    if "b" in only: exp_b(n)
    if "c" in only: exp_c(n)
    if "d" in only: exp_d(n, trials)
    if "e" in only: exp_e(10 if a.quick else 60)
    if "f" in only: exp_f()
    if "g" in only: exp_g((500, 1000, 2000) if a.quick else (1000, 2000, 5000, 10000, 20000, 50000), 3 if a.quick else 10)
    if "h" in only: exp_h(Path(a.attacks_file))
    print(f"[collect] done in {(time.time() - t00) / 60:.1f} min")


if __name__ == "__main__":
    main()
