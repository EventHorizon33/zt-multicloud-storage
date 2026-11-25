#!/usr/bin/env python3
"""Phase 1: per-size breakdown of upload, encryption, decryption and download.

For every (provider mode, chunk size, file size) the harness takes N measurements. Each
measurement is a FRESH server (and, for emulators, a fresh emulator trio), an untimed 1 MiB
warm-up, one timed upload and one timed download of the same file, byte-verified. Inside
the server, wall-clock timers (stages.py; no application file is modified) record the time
spent in the encryption and decryption calls and in the other stages.

Measurements of the different configurations are INTERLEAVED (for each file size, repeat r
runs every configuration, rotating the starting one), so slow or fast periods of the machine
affect all configurations alike.

  cd backend
  .venv/bin/python ../scripts/bench/breakdown.py run \\
      --configs memory:1,memory:16,emulators:1,emulators:16 --plan 5:10,20:10,100:10,200:10,1024:5
  .venv/bin/python ../scripts/bench/breakdown.py summarize ../scripts/bench/results/phase1-<date>

Definitions (all per file, summed over its chunks):
  upload / download   wall time of the whole HTTP request, measured by the client
  encryption          time inside encrypt_chunk: AES-256-GCM encrypt plus SHA-256 of the blob
  decryption          time inside decrypt_chunk: SHA-256 check of the blob plus AES-256-GCM verify
  Confidence intervals are 95% percentile-bootstrap intervals of the median (5000 resamples).
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import bench  # noqa: E402

MIB = bench.MIB
STAGES_PY = HERE / "stages.py"

# stage name -> (registry key, which number: 1 = inclusive, 2 = exclusive)
UP = {
    "encrypt": ("request|encrypt_chunk (AES-256-GCM + SHA-256 of blob)", 1),
    "plain_sha256": ("request|SHA-256 of plaintext (whole-file hash)", 1),
    "replicate": ("request|store_chunk (replicate to R providers)", 2),
    "db_commit": ("request|metadata DB commit (SQLite)", 2),
    "audit": ("request|audit append (SQLite insert + commit)", 2),
    "recv_body": ("request|  of which: multipart read() (waits on network)", 2),
    "service_total": ("request|SERVICE upload() total", 1),
}
DOWN = {
    "decrypt": ("request|decrypt_chunk (SHA-256 check + AES-256-GCM)", 1),
    "fetch": ("request|fetch_chunk (get replica + verify SHA-256)", 1),
    "assemble_rest": ("request|assemble (loop: fetch, decrypt, hash, spool)", 2),
    "audit": ("request|audit append (SQLite insert + commit)", 2),
    "service_total": ("request|SERVICE download() total", 1),
}


def pick(dump: dict, spec: dict) -> dict:
    out = {}
    for name, (key, idx) in spec.items():
        v = dump.get(key)
        out[name] = (v[idx] if v else 0.0)
    return out


def measure(prov: str, chunk_mib: int, size_mib: float, payload: Path, sha: str, warm: Path) -> dict:
    import httpx
    size = int(size_mib * MIB)
    work = Path(tempfile.mkdtemp(prefix="zt-bd-"))
    stage_out = work / "stages"
    stage_out.mkdir()
    emu = bench.ManagedEmulators() if prov == "emulators" else None
    env = dict(os.environ)
    if emu:
        env.update(emu.start())
    env["ZT_STAGE_OUT"] = str(stage_out)
    port = bench.free_port()
    srv = subprocess.Popen([sys.executable, str(STAGES_PY), "serve", "--port", str(port), "--data-dir", str(work / "data"),
                            "--providers", prov, "--chunk-bytes", str(chunk_mib * MIB), "--max-upload", str(size + 16 * MIB)],
                           env=env, cwd=bench.BACKEND, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        c = httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=None)
        for _ in range(400):
            if srv.poll() is not None:
                raise RuntimeError("server exited: " + srv.stderr.read().decode(errors="replace")[-600:])
            try:
                if c.get("/api/health").status_code == 200:
                    break
            except httpx.TransportError:
                pass
            time.sleep(0.1)
        else:
            raise RuntimeError("server not healthy")
        assert c.post("/api/auth/register", json={"username": "benchuser", "password": bench.PASSWORD}).status_code == 202

        def token() -> dict:
            r = c.post("/api/auth/login", json={"username": "benchuser", "password": bench.PASSWORD})
            assert r.status_code == 200, r.text
            return {"Authorization": "Bearer " + r.json()["access_token"]}

        def upload(path: Path, h: dict):
            with open(path, "rb") as f:
                return c.post("/api/files", headers=h, files={"file": ("bench.bin", f, "application/octet-stream")})

        def wait_dump(n: int) -> dict:
            p = stage_out / f"stages-{n}.json"
            for _ in range(300):
                if p.exists():
                    try:
                        return json.loads(p.read_text())
                    except json.JSONDecodeError:
                        pass
                time.sleep(0.05)
            raise RuntimeError(f"no stage dump {n}")

        h = token()                                         # untimed warm-up
        r = upload(warm, h)
        assert r.status_code == 201, r.text
        with c.stream("GET", f"/api/files/{r.json()['id']}/download", headers=h) as d:
            for _ in d.iter_bytes(MIB):
                pass
        h_up, h_down = token(), token()                     # fetched BEFORE the timers are reset
        os.kill(srv.pid, signal.SIGUSR2)
        time.sleep(0.2)

        t0 = time.perf_counter()
        r = upload(payload, h_up)
        t_up = time.perf_counter() - t0
        assert r.status_code == 201, f"upload failed {r.status_code} {r.text[:300]}"
        fid = r.json()["id"]
        os.kill(srv.pid, signal.SIGUSR1)
        d_up = wait_dump(1)

        out = work / "down.bin"
        t_first = None
        t0 = time.perf_counter()
        with c.stream("GET", f"/api/files/{fid}/download", headers=h_down) as d:
            assert d.status_code == 200, d.status_code
            with open(out, "wb") as f:
                for blk in d.iter_bytes(4 * MIB):
                    if t_first is None:
                        t_first = time.perf_counter() - t0
                    f.write(blk)
        t_down = time.perf_counter() - t0
        os.kill(srv.pid, signal.SIGUSR1)
        d_down = wait_dump(2)
        ok = out.stat().st_size == size and bench.sha256_file(out) == sha
        return dict(upload_s=t_up, download_s=t_down, download_ttfb_s=t_first, verified=ok,
                    server_peak_rss_mib=bench.vm_hwm_mib(srv.pid), up=pick(d_up, UP), down=pick(d_down, DOWN))
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=30)
        except subprocess.TimeoutExpired:
            srv.kill()
        if emu:
            emu.stop()
        shutil.rmtree(work, ignore_errors=True)


def cmd_run(a) -> None:
    configs = [(c.split(":")[0], int(c.split(":")[1])) for c in a.configs.split(",")]
    plan = [(float(x.split(":")[0]), int(x.split(":")[1])) for x in a.plan.split(",")]
    out = Path(a.out) if a.out else HERE / "results" / f"phase1-{datetime.now():%Y%m%d-%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    meta = dict(env=bench.environment_info(), configs=a.configs, plan=a.plan, started=datetime.now().astimezone().isoformat(timespec="seconds"))
    (out / "meta.json").write_text(json.dumps(meta, indent=1))
    rows_path = out / "measurements.jsonl"
    tmp = Path(tempfile.mkdtemp(prefix="zt-bd-payload-"))
    warm = tmp / "warm.bin"
    bench.make_payload(warm, MIB)
    try:
        for size_mib, reps in plan:
            payload = tmp / f"p{size_mib:g}.bin"
            bench.make_payload(payload, int(size_mib * MIB))
            sha = bench.sha256_file(payload)
            for r in range(reps):
                order = configs[r % len(configs):] + configs[:r % len(configs)]      # rotate the starting configuration
                for prov, chunk in order:
                    t = time.time()
                    for attempt in (1, 2):
                        try:
                            m = measure(prov, chunk, size_mib, payload, sha, warm)
                            break
                        except Exception as exc:                                      # one retry for a transient failure
                            print(f"[breakdown] {prov}:{chunk} {size_mib:g} MiB rep {r} attempt {attempt} failed: {str(exc)[:200]}",
                                  file=sys.stderr, flush=True)
                            m = None
                    if m is None:
                        continue
                    m.update(provider=prov, chunk_mib=chunk, size_mib=size_mib, rep=r, ended=time.time())
                    with open(rows_path, "a") as f:
                        f.write(json.dumps(m) + "\n")
                    print(f"[breakdown] {size_mib:g} MiB rep {r + 1}/{reps} {prov}:{chunk} up {m['upload_s']:.2f}s "
                          f"down {m['download_s']:.2f}s enc {m['up']['encrypt']*1000:.0f}ms dec {m['down']['decrypt']*1000:.0f}ms "
                          f"verified={m['verified']} ({time.time() - t:.0f}s)", flush=True)
            payload.unlink()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"[breakdown] wrote {out}")


# --------------------------------------------------------------------------- #
# statistics
# --------------------------------------------------------------------------- #
def boot_ci(xs: list[float], b: int = 5000, seed: int = 12345) -> tuple[float, float]:
    if len(xs) < 2:
        return (xs[0], xs[0]) if xs else (float("nan"), float("nan"))
    rng = random.Random(seed)
    n = len(xs)
    meds = sorted(statistics.median(rng.choices(xs, k=n)) for _ in range(b))
    return meds[int(0.025 * b)], meds[int(0.975 * b) - 1]


def stat(xs: list[float]) -> dict:
    lo, hi = boot_ci(xs)
    return dict(n=len(xs), median=statistics.median(xs), ci_lo=lo, ci_hi=hi, min=min(xs), max=max(xs),
                mean=statistics.fmean(xs), stdev=statistics.stdev(xs) if len(xs) > 1 else 0.0)


def cmd_summarize(a) -> None:
    d = Path(a.dir)
    rows = [json.loads(line) for line in (d / "measurements.jsonl").read_text().splitlines() if line.strip()]
    bad = [r for r in rows if not r["verified"]]
    groups: dict = {}
    for r in rows:
        groups.setdefault((r["provider"], r["chunk_mib"], r["size_mib"]), []).append(r)
    summary = {"meta": json.loads((d / "meta.json").read_text()), "unverified": len(bad), "cells": []}
    for (prov, chunk, size), rs in sorted(groups.items()):
        cell = dict(provider=prov, chunk_mib=chunk, size_mib=size, n=len(rs))
        cell["upload_s"] = stat([r["upload_s"] for r in rs])
        cell["download_s"] = stat([r["download_s"] for r in rs])
        cell["download_ttfb_s"] = stat([r["download_ttfb_s"] for r in rs])
        for k in ("encrypt", "plain_sha256", "replicate", "db_commit", "audit", "recv_body", "service_total"):
            cell[f"up_{k}_s"] = stat([r["up"][k] for r in rs])
        for k in ("decrypt", "fetch", "assemble_rest", "audit", "service_total"):
            cell[f"down_{k}_s"] = stat([r["down"][k] for r in rs])
        cell["upload_mib_s"] = stat([size / r["upload_s"] for r in rs])
        cell["download_mib_s"] = stat([size / r["download_s"] for r in rs])
        cell["encrypt_share_of_upload"] = statistics.median(r["up"]["encrypt"] / r["upload_s"] for r in rs)
        cell["decrypt_share_of_download"] = statistics.median(r["down"]["decrypt"] / r["download_s"] for r in rs)
        cell["server_rss_mib"] = max((r["server_peak_rss_mib"] or 0) for r in rs)
        summary["cells"].append(cell)
    (d / "summary.json").write_text(json.dumps(summary, indent=1))
    (d / "BREAKDOWN.md").write_text(render_md(summary))
    print(render_md(summary))
    print(f"[breakdown] wrote {d / 'summary.json'} and BREAKDOWN.md")


def fmt_s(x: float) -> str:
    return f"{x * 1000:.0f} ms" if x < 1 else f"{x:.2f} s" if x < 10 else f"{x:.1f} s"


def cell_txt(s: dict) -> str:
    return f"{fmt_s(s['median'])} [{fmt_s(s['ci_lo'])}-{fmt_s(s['ci_hi'])}]"


def render_md(sm: dict) -> str:
    env = sm["meta"]["env"]
    out = ["# Per-size breakdown: upload, encryption, decryption, download\n",
           f"- Machine: {env['cpu']}, {env['logical_cpus']} logical CPUs, {env['mem_total_mib']} MiB RAM; Python {env['python']}; "
           f"commit {env['git_commit']}; {env['platform']}",
           f"- Start state: load average {env.get('loadavg_1m', 'n/a')}, {env.get('mem_available_mib', 'n/a')} MiB memory available, "
           f"{env.get('disk_free_gib_tmp', 'n/a')} GiB disk free",
           "- Cells are `median [95% bootstrap CI of the median]` over n measurements. Encryption and decryption are the "
           "in-server time inside encrypt_chunk (AES-256-GCM plus SHA-256 of the blob) and decrypt_chunk (SHA-256 check plus "
           "AES-256-GCM verify), summed over the file's chunks. Upload and download are whole-request wall times.",
           f"- Unverified transfers: {sm['unverified']}\n"]
    for prov in ("emulators", "memory"):
        for chunk in sorted({c["chunk_mib"] for c in sm["cells"]}):
            cells = [c for c in sm["cells"] if c["provider"] == prov and c["chunk_mib"] == chunk]
            if not cells:
                continue
            out.append(f"\n## {prov} providers, {chunk} MiB chunks\n")
            out.append("| File | n | Upload | Encryption | Decryption | Download | Encrypt share of upload | Decrypt share of download |")
            out.append("|---:|---:|---:|---:|---:|---:|---:|---:|")
            for c in cells:
                out.append(f"| {c['size_mib']:g} MiB | {c['n']} | {cell_txt(c['upload_s'])} | {cell_txt(c['up_encrypt_s'])} | "
                           f"{cell_txt(c['down_decrypt_s'])} | {cell_txt(c['download_s'])} | "
                           f"{100 * c['encrypt_share_of_upload']:.0f}% | {100 * c['decrypt_share_of_download']:.0f}% |")
            out.append("\nWhere the rest of the upload goes (median, ms; request thread):\n")
            out.append("| File | Replication | Metadata commits | Audit | Plaintext SHA-256 | Body read |")
            out.append("|---:|---:|---:|---:|---:|---:|")
            for c in cells:
                g = lambda k: f"{c[k]['median'] * 1000:.0f}"
                out.append(f"| {c['size_mib']:g} MiB | {g('up_replicate_s')} | {g('up_db_commit_s')} | {g('up_audit_s')} | {g('up_plain_sha256_s')} | {g('up_recv_body_s')} |")
            out.append("\nWhere the rest of the download goes (median, ms; request thread):\n")
            out.append("| File | Fetch and verify replica | Audit | Plaintext hash and spool write | Time to first byte |")
            out.append("|---:|---:|---:|---:|---:|")
            for c in cells:
                g = lambda k: f"{c[k]['median'] * 1000:.0f}"
                out.append(f"| {c['size_mib']:g} MiB | {g('down_fetch_s')} | {g('down_audit_s')} | {g('down_assemble_rest_s')} | {g('download_ttfb_s')} |")
    return "\n".join(out) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--configs", default="memory:1,memory:16,emulators:1,emulators:16")
    r.add_argument("--plan", default="5:10,20:10,100:10,200:10,1024:5", help="size_mib:repeats,...")
    r.add_argument("--out")
    s = sub.add_parser("summarize")
    s.add_argument("dir")
    a = ap.parse_args()
    {"run": cmd_run, "summarize": cmd_summarize}[a.cmd](a)


if __name__ == "__main__":
    main()
