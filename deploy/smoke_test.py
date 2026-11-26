#!/usr/bin/env python3
"""Smoke test for the container deployment (deploy/docker-compose.yml), run against the published nginx port.

  ZT_SMOKE_ADMIN_PASSWORD=... python deploy/smoke_test.py [http://127.0.0.1:8080]

Checks, through nginx exactly as a browser would reach the backend: the SPA and /api/health are served, /metrics is not proxied, the
bootstrap admin can sign in (password-only sessions are restricted), a new user registers, enrols TOTP and signs in with a code, uploads
a multi-chunk file (ZT_SMOKE_SIZE_MIB, default 20), sees the chunk map (two replicas per chunk on distinct providers), and downloads the file byte for byte (SHA-256).
It prints no password, token or TOTP secret. Needs httpx and pyotp (both are in backend/requirements.txt).
"""
from __future__ import annotations

import hashlib
import os
import secrets
import sys
import time

import httpx
import pyotp

URL = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ZT_SMOKE_URL", "http://127.0.0.1:8080")).rstrip("/")
ADMIN_USER = os.environ.get("ZT_SMOKE_ADMIN_USER", "admin")
ADMIN_PW = os.environ.get("ZT_SMOKE_ADMIN_PASSWORD", "")
SIZE = int(float(os.environ.get("ZT_SMOKE_SIZE_MIB", "20")) * 1024 * 1024) + 12345   # ZT_SMOKE_SIZE_MIB=300 exercises the large-file settings
RESULTS: list[tuple[bool, str]] = []


def check(ok: bool, what: str) -> None:
    RESULTS.append((ok, what))
    print(f"[{'PASS' if ok else 'FAIL'}] {what}", flush=True)


def main() -> int:
    http = httpx.Client(base_url=URL, timeout=120)
    r = http.get("/")
    check(r.status_code == 200 and "<div id=\"root\"" in r.text, f"GET / serves the single-page app ({r.status_code})")
    r = http.get("/api/health")
    check(r.status_code == 200, f"GET /api/health through nginx -> {r.status_code} {r.json() if r.status_code == 200 else ''}")
    r = http.get("/metrics")
    check(r.status_code in (403, 404) or "text/html" in r.headers.get("content-type", ""), f"/metrics is not proxied to the backend ({r.status_code})")

    if ADMIN_PW:
        r = http.post("/api/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PW})
        check(r.status_code == 200 and r.json().get("mfa_verified") is False, f"bootstrap admin password login -> {r.status_code}, session restricted until MFA")

    name, pw = "smoke" + secrets.token_hex(3), "Pw3-" + secrets.token_urlsafe(18)
    r = http.post("/api/auth/register", json={"username": name, "password": pw})
    check(r.status_code == 202, f"register a new user -> {r.status_code}")
    r = http.post("/api/auth/login", json={"username": name, "password": pw})
    check(r.status_code == 200, f"user password login -> {r.status_code}")
    hdr = {"Authorization": "Bearer " + r.json()["access_token"]}
    enr = http.post("/api/auth/mfa/enroll", headers=hdr)
    secret = enr.json()["secret"]
    step = int(time.time() // 30)
    act = http.post("/api/auth/mfa/activate", headers=hdr, json={"code": pyotp.TOTP(secret).at(step * 30)})
    check(enr.status_code == 200 and act.status_code == 200, f"enrol and activate TOTP -> {enr.status_code}/{act.status_code}")
    while int(time.time() // 30) <= step:           # the server accepts each time step once
        time.sleep(0.5)
    step = int(time.time() // 30)
    r = http.post("/api/auth/login", json={"username": name, "password": pw, "totp_code": pyotp.TOTP(secret).at(step * 30)})
    check(r.status_code == 200 and r.json().get("mfa_verified") is True, f"login with password and TOTP code -> {r.status_code}, mfa_verified={r.json().get('mfa_verified')}")
    hdr = {"Authorization": "Bearer " + r.json()["access_token"]}

    data = os.urandom(SIZE)                         # default 20 MiB + a bit: two 16 MiB chunks with the deployment setting
    sha = hashlib.sha256(data).hexdigest()
    r = http.post("/api/files", headers=hdr, files={"file": ("smoke.bin", data, "application/octet-stream")}, data={"classification": "internal"})
    ok = r.status_code == 201
    meta = r.json() if ok else {}
    check(ok and meta.get("status") == "committed", f"upload {len(data):,} bytes -> {r.status_code}, chunks={meta.get('chunk_count')}, chunk_size={meta.get('chunk_size')}")
    check(meta.get("chunk_size") == 16 * 1024 * 1024, "the file was cut with the deployment chunk size of 16 MiB")
    fid = meta.get("id")
    r = http.get(f"/api/files/{fid}/distribution", headers=hdr)
    dist = r.json() if r.status_code == 200 else {"chunks": []}
    check(r.status_code == 200 and dist["chunks"] and all(len({x["provider"] for x in c["replicas"]}) == 2 for c in dist["chunks"]),
          "chunk map: every chunk has two replicas on two distinct providers")
    r = http.get(f"/api/files/{fid}/download", headers=hdr)
    check(r.status_code == 200 and hashlib.sha256(r.content).hexdigest() == sha, f"download -> {r.status_code}, SHA-256 identical to the upload")

    failed = [w for ok_, w in RESULTS if not ok_]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
