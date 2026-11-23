#!/usr/bin/env python3
"""End-to-end demonstration against the REAL running server (HTTP via httpx)
and the REAL storage emulators (raw boto3 / azure-storage-blob /
google-cloud-storage clients). Started by ``scripts/demo.sh``, which provides:

  ZT_DEMO_URL            base URL of the running backend
  ZT_DEMO_DATA_DIR       the server's (temporary) data dir (for the audit DB)
  ZT_DEMO_ADMIN_USER     bootstrap admin username
  ZT_DEMO_ADMIN_PASSWORD bootstrap admin password (generated per run, never printed)
  ZT_DEMO_EMULATORS_SH   path to scripts/emulators.sh
  ZT_S3_* / ZT_AZURE_* / ZT_GCS_*   emulator endpoints (scripts/.emulators/run/emulators.env)

The server runs with its default policy ``require_mfa_for_login=true``
(ADR-0010): every account enrols TOTP (pyotp) inside the self-enrolment window
right after registration and then signs in again with a code; activating a
factor never upgrades the session that started the enrolment.

No access token, refresh token, password, TOTP seed or TOTP code is ever printed.
Exit status 0 only if every step's checks passed."""
from __future__ import annotations

import hashlib
import math
import os
import secrets
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

import httpx
import pyotp

URL = os.environ.get("ZT_DEMO_URL", "")
DATA = Path(os.environ.get("ZT_DEMO_DATA_DIR", "."))
ADMIN_USER = os.environ.get("ZT_DEMO_ADMIN_USER", "")
ADMIN_PW = os.environ.get("ZT_DEMO_ADMIN_PASSWORD", "")
EMU = os.environ.get("ZT_DEMO_EMULATORS_SH", "")
TOTAL = 16
MARKER = b"ZT-DEMO-PLAINTEXT-MARKER::quarterly-figures"
FILENAME = "q3-board-financials.xlsx"
CHECKS: list[tuple[int, str, bool]] = []
STEP = [0]


# --------------------------------------------------------------------------- #
# output helpers
# --------------------------------------------------------------------------- #
def step(title: str) -> None:
    STEP[0] += 1
    print()
    print("=" * 100)
    print(f"[{STEP[0]:>2}/{TOTAL}] {title}")
    print("=" * 100)


def say(msg: str = "") -> None:
    print("    " + msg)


def check(cond: bool, what: str) -> None:
    CHECKS.append((STEP[0], what, bool(cond)))
    print(f"    [{'PASS' if cond else 'FAIL'}] {what}")


def table(rows: list[list], head: list[str]) -> None:
    rows = [[str(c) for c in r] for r in rows]
    w = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(head)]
    say("  ".join(h.ljust(x) for h, x in zip(head, w)))
    say("  ".join("-" * x for x in w))
    for r in rows:
        say("  ".join(c.ljust(x) for c, x in zip(r, w)))


def entropy(b: bytes) -> float:
    c = Counter(b)
    return -sum(n / len(b) * math.log2(n / len(b)) for n in c.values()) if b else 0.0


# --------------------------------------------------------------------------- #
# HTTP client (tokens stay inside these objects)
# --------------------------------------------------------------------------- #
class Client:
    def __init__(self, label: str) -> None:
        self.label = label
        self.http = httpx.Client(base_url=URL, timeout=60)
        self.token: str | None = None
        self.totp_secret: str | None = None
        self.used_step = -1                 # last TOTP time step sent (the server refuses replays)

    def h(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def req(self, method: str, path: str, **kw) -> httpx.Response:
        headers = {**self.h(), **kw.pop("headers", {})}
        return self.http.request(method, path, headers=headers, **kw)

    def login(self, username: str, password: str, totp: str | None = None) -> httpx.Response:
        body = {"username": username, "password": password}
        if totp:
            body["totp_code"] = totp
        r = self.http.post("/api/auth/login", json=body)
        if r.status_code == 200:
            self.token = r.json()["access_token"]
        return r

    def code(self) -> str:
        """A TOTP code from a time step this client has not used yet (waits for
        the next 30 s step if needed: the server accepts each step only once)."""
        while int(time.time() // 30) <= self.used_step:
            time.sleep(0.5)
        self.used_step = int(time.time() // 30)
        return pyotp.TOTP(self.totp_secret).at(self.used_step * 30)

    def enrol_totp(self) -> tuple[httpx.Response, httpx.Response]:
        """Enrol + activate a TOTP factor from the current (password-only) session."""
        enr = self.req("POST", "/api/auth/mfa/enroll")
        if enr.status_code != 200:
            return enr, enr
        self.totp_secret = enr.json()["secret"]
        return enr, self.req("POST", "/api/auth/mfa/activate", json={"code": self.code()})


def emu(*args: str) -> str:
    out = subprocess.run([EMU, *args], capture_output=True, text=True, timeout=120)
    return (out.stdout + out.stderr).strip()


# --------------------------------------------------------------------------- #
# raw SDK access to the emulators (the "attacker with a provider credential" view)
# --------------------------------------------------------------------------- #
def sdk_clients() -> dict:
    import boto3
    from azure.storage.blob import BlobServiceClient
    from google.auth.credentials import AnonymousCredentials
    from google.cloud import storage as gcs

    s3 = boto3.client("s3", endpoint_url=os.environ["ZT_S3_ENDPOINT_URL"], region_name=os.environ["ZT_S3_REGION"],
                      aws_access_key_id=os.environ["ZT_S3_ACCESS_KEY_ID"],
                      aws_secret_access_key=os.environ["ZT_S3_SECRET_ACCESS_KEY"])
    az = BlobServiceClient.from_connection_string(os.environ["ZT_AZURE_CONNECTION_STRING"]) \
        .get_container_client(os.environ["ZT_AZURE_CONTAINER"])
    g = gcs.Client(project=os.environ["ZT_GCS_PROJECT"], credentials=AnonymousCredentials(),
                   client_options={"api_endpoint": os.environ["ZT_GCS_ENDPOINT_URL"]}) \
        .bucket(os.environ["ZT_GCS_BUCKET"])
    s3_bucket = os.environ["ZT_S3_BUCKET"]
    return {
        "aws-s3": (lambda k: s3.get_object(Bucket=s3_bucket, Key=k)["Body"].read(),
                   lambda k, d: s3.put_object(Bucket=s3_bucket, Key=k, Body=d),
                   lambda k: s3.head_object(Bucket=s3_bucket, Key=k).get("Metadata", {})),
        "azure-blob": (lambda k: az.download_blob(k).readall(),
                       lambda k, d: az.upload_blob(k, d, overwrite=True),
                       lambda k: dict(az.get_blob_client(k).get_blob_properties().metadata or {})),
        "gcs": (lambda k: g.blob(k).download_as_bytes(),
                lambda k, d: g.blob(k).upload_from_string(d),
                lambda k: dict(g.get_blob(k).metadata or {})),
    }


# --------------------------------------------------------------------------- #
def main() -> int:
    admin, alice, bob, anon = Client("admin"), Client("alice"), Client("bob"), Client("anonymous")
    alice_pw = "Pw1-" + secrets.token_urlsafe(16)          # random per run, never printed
    bob_pw = "Pw2-" + secrets.token_urlsafe(16)
    data = MARKER + os.urandom(3 * 1024 * 1024 + 512 * 1024) + MARKER       # 3.5 MiB -> 4 chunks of 1 MiB
    local_sha = hashlib.sha256(data).hexdigest()

    # 1 ---------------------------------------------------------------------
    step("Environment: three storage emulators + the backend server (real HTTP)")
    say(emu("status").replace("\n", "\n    "))
    r = anon.req("GET", "/api/health")
    say(f"GET /api/health -> {r.status_code} {r.json()}")
    check(r.status_code == 200 and r.json()["status"] == "ok", "server is up and its database is reachable")

    # 2 ---------------------------------------------------------------------
    step("Bootstrap admin: password-only session is restricted; enrol TOTP, then sign in again WITH the code")
    r = admin.login(ADMIN_USER, ADMIN_PW)
    check(r.status_code == 200, f"admin password login -> {r.status_code} (role={r.json()['user']['role']}, "
                                f"mfa_verified={r.json()['mfa_verified']})")
    me = admin.req("GET", "/api/auth/me").json()
    r = admin.req("GET", "/api/admin/users")
    check(me["restricted"] is True and r.status_code == 403 and r.json()["reasons"] == ["mfa-enrollment-required"],
          f"require_mfa_for_login=true (default): session restricted, GET /api/admin/users -> {r.status_code} "
          f"{r.json()['reasons']}")
    enr, act = admin.enrol_totp()
    check(enr.status_code == 200 and act.status_code == 200 and act.json()["mfa_fresh"] is False
          and act.json()["restricted"] is True,
          "bootstrap admin enrols + activates TOTP; activation does NOT upgrade this session (ADR-0010)")
    r = admin.login(ADMIN_USER, ADMIN_PW, totp=admin.code())
    me = admin.req("GET", "/api/auth/me").json()
    check(r.status_code == 200 and r.json()["mfa_verified"] is True and me["restricted"] is False,
          "new login with password + TOTP -> MFA-verified session (secret and codes not printed)")

    # 3 ---------------------------------------------------------------------
    step("Register two users (alice = user, bob = auditor); registration never reveals existing names")
    for name, pw in (("alice", alice_pw), ("bob", bob_pw)):
        r = anon.req("POST", "/api/auth/register", json={"username": name, "password": pw})
        check(r.status_code == 202 and r.json() == {"status": "accepted"},
              f"register {name} -> {r.status_code} {r.json()} (no role can be chosen)")
    r = anon.req("POST", "/api/auth/register", json={"username": "alice", "password": "Pw3-" + secrets.token_urlsafe(16)})
    check(r.status_code == 202 and r.json() == {"status": "accepted"},
          f"register an EXISTING name (alice) -> {r.status_code} {r.json()}: identical answer, no duplicate (F3)")
    users = {u["username"]: u for u in admin.req("GET", "/api/admin/users").json()["users"]}
    check(users["alice"]["role"] == users["bob"]["role"] == "user", "both accounts exist with role=user")
    r = admin.req("PUT", f"/api/admin/users/{users['bob']['id']}/role", json={"role": "auditor"})
    check(r.status_code == 200 and r.json()["role"] == "auditor", "admin (fresh MFA) promotes bob to auditor")
    users = admin.req("GET", "/api/admin/users").json()["users"]
    table([[u["username"], u["role"], u["clearance"], u["mfa_enabled"]] for u in users],
          ["username", "role", "clearance", "mfa"])
    check(all("audit_pseudonym" not in u for u in users),
          "the user directory carries no audit pseudonyms (only the audited pseudonym lookup maps them)")

    # 4 ---------------------------------------------------------------------
    step("Both users enrol TOTP inside the 24 h self-enrolment window, then sign in with password + code")
    for c, name, pw in ((alice, "alice", alice_pw), (bob, "bob", bob_pw)):
        r = c.login(name, pw)
        check(r.status_code == 200 and r.json()["mfa_verified"] is False,
              f"{name} password login -> {r.status_code} (restricted until MFA)")
        enr, act = c.enrol_totp()
        check(enr.status_code == 200 and act.status_code == 200 and act.json()["mfa_fresh"] is False,
              f"{name} enrols + activates TOTP (basis: trust-on-first-use window); session stays password-only")
    for c, name, pw in ((alice, "alice", alice_pw), (bob, "bob", bob_pw)):
        r = c.login(name, pw, totp=c.code())
        check(r.status_code == 200 and r.json()["mfa_verified"] is True,
              f"{name} login with TOTP -> {r.status_code}, mfa_verified=True, expires_in={r.json()['expires_in']}s, "
              "refresh token in HttpOnly cookie")
        me = c.req("GET", "/api/auth/me").json()
        say(f"    {name}: role={me['user']['role']} restricted={me['restricted']} "
            f"session={me['session']['id'][:8]}... pseudonym={me['audit_pseudonym']}")
    r = bob.req("GET", "/api/admin/users")
    check(r.status_code == 403,
          f"auditor bob: GET /api/admin/users -> {r.status_code} {r.json()['reasons']} "
          "(auditors work with pseudonyms; no user directory)")

    # 5 ---------------------------------------------------------------------
    step(f"alice uploads a sample file ({len(data):,} bytes, filename '{FILENAME}')")
    r = alice.req("POST", "/api/files", files={"file": (FILENAME, data, "application/vnd.ms-excel")},
                  data={"classification": "internal"})
    meta = r.json()
    check(r.status_code == 201 and meta["status"] == "committed", f"POST /api/files -> {r.status_code}, "
                                                                   f"status={meta.get('status')}")
    fid = meta["id"]
    say(f"file id={fid}  size={meta['size_bytes']:,}  chunks={meta['chunk_count']}  "
        f"chunk_size={meta['chunk_size']:,}  classification={meta['classification']}")
    say(f"local SHA-256 of the plaintext: {local_sha}")

    # 6 ---------------------------------------------------------------------
    step("Chunks and their distribution across the three providers (R=2 of 3)")
    dist = alice.req("GET", f"/api/files/{fid}/distribution").json()
    table([[c["index"], c["chunk_id"], f"{c['ciphertext_size']:,}", ", ".join(r["provider"] for r in c["replicas"])]
           for c in dist["chunks"]], ["idx", "opaque object id", "bytes", "replicas"])
    say(f"replicas per provider: {dist['providers']}  (replication_factor={dist['replication_factor']})")
    check(all(len(c["replicas"]) == 2 for c in dist["chunks"]), "every chunk has 2 replicas on distinct providers")
    check(all(n > 0 for n in dist["providers"].values()), "all three providers hold some chunks; none holds all")

    # 7 ---------------------------------------------------------------------
    step("Encryption and integrity metadata from the distribution endpoint")
    say("each chunk = nonce(12) || AES-256-GCM(ciphertext || tag(16)); AAD = (version, file id, index, final flag)")
    say("SHA-256 of every stored blob is fixed in the HMAC-sealed manifest (checked on every read):")
    table([[c["index"], c["ciphertext_sha256"]] for c in dist["chunks"]], ["idx", "ciphertext SHA-256"])
    overhead = sum(c["ciphertext_size"] for c in dist["chunks"]) - len(data)
    check(overhead == 28 * len(dist["chunks"]), f"ciphertext overhead = {overhead} bytes = 28 per chunk "
                                                "(12-byte nonce + 16-byte GCM tag)")

    # 8 ---------------------------------------------------------------------
    step("Read the raw objects DIRECTLY from the emulators with the cloud SDKs (provider-credential view)")
    sdk = sdk_clients()
    rows, ok_hash, ok_marker, ok_meta = [], True, True, True
    for c in dist["chunks"]:
        for rep in c["replicas"]:
            blob = sdk[rep["provider"]][0](c["chunk_id"])
            md = sdk[rep["provider"]][2](c["chunk_id"])
            h = hashlib.sha256(blob).hexdigest()
            ok_hash &= h == c["ciphertext_sha256"]
            ok_marker &= MARKER not in blob and FILENAME.encode() not in blob and b"alice" not in blob
            ok_meta &= not md
            rows.append([c["index"], rep["provider"], f"{len(blob):,}", blob[:12].hex(), f"{entropy(blob):.3f}",
                         "match" if h == c["ciphertext_sha256"] else "MISMATCH", md or "{}"])
    table(rows, ["idx", "provider", "bytes", "first 12 bytes (nonce)", "bits/byte", "sha256", "metadata"])
    check(ok_hash, "every raw object's SHA-256 equals the manifest value")
    check(ok_marker, f"plaintext marker, filename and username absent from every object")
    check(ok_meta, "no object metadata (no owner, no filename, no key id) at any provider")

    # 9 ---------------------------------------------------------------------
    step("alice downloads the file; compare SHA-256")
    r = alice.req("GET", f"/api/files/{fid}/download")
    got = hashlib.sha256(r.content).hexdigest()
    say(f"GET /download -> {r.status_code}, {len(r.content):,} bytes, X-Content-SHA256={r.headers.get('x-content-sha256')}")
    say(f"Content-Disposition: {r.headers.get('content-disposition')}")
    say(f"downloaded SHA-256: {got}")
    check(r.status_code == 200 and got == local_sha == r.headers.get("x-content-sha256"),
          "downloaded plaintext is byte-identical to the original")

    # 10 --------------------------------------------------------------------
    step("bob (auditor) and an anonymous client try to access alice's file")
    for label, method, path in (("download", "GET", f"/api/files/{fid}/download"),
                                ("metadata", "GET", f"/api/files/{fid}"),
                                ("delete", "DELETE", f"/api/files/{fid}")):
        r = bob.req(method, path)
        check(r.status_code == 404 and MARKER not in r.content,
              f"bob {label}: {r.status_code} {r.json()} (same as a non-existent id)")
    r = anon.req("GET", f"/api/files/{fid}/download")
    check(r.status_code == 401, f"no token: {r.status_code} {r.json()['error']}")
    r = admin.req("GET", f"/api/files/{fid}/download")
    check(r.status_code == 403 and r.json()["reasons"] == ["admin-no-content-access"],
          f"even the admin: {r.status_code} {r.json()['reasons']} (separation of duties)")
    bob_pseudo = bob.req("GET", "/api/auth/me").json()["audit_pseudonym"]
    denies = bob.req("GET", "/api/audit/events", params={"actor": bob_pseudo, "event_type": "authz.decision",
                                                        "outcome": "denied", "order": "asc"}).json()["events"]
    table([[e["seq"], e["event_type"], e["outcome"], e["severity"], e["action"], ",".join(e["details"]["reasons"])]
           for e in denies], ["seq", "event", "outcome", "severity", "action", "reasons"])
    check(len(denies) >= 3, "each attempt is in the audit log as authz.decision denied")
    deny_seq = denies[0]["seq"]

    # 11 --------------------------------------------------------------------
    step("Tamper with a stored chunk at ONE provider (overwrite via the SDK) -> detection")
    c1 = dist["chunks"][1]
    target = c1["replicas"][0]["provider"]
    blob = bytearray(sdk[target][0](c1["chunk_id"]))
    blob[100] ^= 0xFF
    sdk[target][1](c1["chunk_id"], bytes(blob))
    say(f"flipped one byte of chunk 1 ({c1['chunk_id'][:12]}...) at {target}")
    v = alice.req("POST", f"/api/files/{fid}/verify").json()
    say(f"POST /verify -> healthy={v['healthy']} recoverable={v['recoverable']} summary={v['summary']}")
    check(v["healthy"] is False and v["summary"]["corrupt"] == 1, "scrub finds the corrupt replica without decrypting")
    r = alice.req("GET", f"/api/files/{fid}/download")
    check(r.status_code == 200 and hashlib.sha256(r.content).hexdigest() == local_sha,
          "download still byte-identical (served from the intact replica)")
    crit = bob.req("GET", "/api/audit/events", params={"event_type": "storage.replica.corrupt",
                                                      "resource_id": c1["chunk_id"]}).json()["events"]
    for e in crit:
        say(f"audit: seq={e['seq']} {e['event_type']} {e['outcome']} {e['severity']} provider={e['details']['provider']}")
    check(bool(crit) and crit[0]["severity"] == "critical", "critical audit event storage.replica.corrupt")
    rp = alice.req("POST", f"/api/files/{fid}/repair").json()
    v = alice.req("POST", f"/api/files/{fid}/verify").json()
    check(rp["ok"] and v["healthy"], f"repair re-replicated chunk(s) {rp['repaired_chunks']} -> verify healthy")

    # 12 --------------------------------------------------------------------
    step("Tamper with an audit record directly in the audit database (attacker with DB access)")
    db = sqlite3.connect(DATA / "audit.db", isolation_level=None, timeout=10)
    before = db.execute("SELECT seq, event_type, outcome FROM audit_events WHERE seq=?", (deny_seq,)).fetchone()
    db.execute("UPDATE audit_events SET outcome='success', severity='info' WHERE seq=?", (deny_seq,))
    after = db.execute("SELECT seq, event_type, outcome FROM audit_events WHERE seq=?", (deny_seq,)).fetchone()
    db.close()
    say(f"UPDATE audit_events: {before} -> {after}  (hide bob's denied attempt)")
    rep = bob.req("POST", "/api/audit/verify", json={}).json()
    say(f"POST /api/audit/verify (as auditor bob) -> ok={rep['ok']} events_checked={rep['events_checked']} "
        f"checkpoints={rep['checkpoints_checked']} anchors={rep['anchors_checked']}")
    for f in rep["findings"][:6]:
        say(f"finding: type={f['type']} seq={f['seq']} detail={f['detail']}")
    check(rep["ok"] is False and any(f["type"] == "record-modified" and f["seq"] == deny_seq for f in rep["findings"]),
          f"verification reports record-modified at seq {deny_seq}")
    av = bob.req("GET", "/api/audit/events", params={"event_type": "audit.verify", "limit": 1}).json()["events"][0]
    say(f"audit: seq={av['seq']} {av['event_type']} {av['outcome']} {av['severity']} "
        f"finding_types={av['details'].get('finding_types')}")
    check(av["severity"] == "critical" and av["outcome"] == "failure", "the verification run itself is audited (critical)")

    # 13 --------------------------------------------------------------------
    step("Stop one emulator process (gcp-storage-emulator) -> failover")
    say(emu("stop-one", "gcs"))
    t0 = time.time()
    r = alice.req("GET", f"/api/files/{fid}/download")
    check(r.status_code == 200 and hashlib.sha256(r.content).hexdigest() == local_sha,
          f"download with GCS down -> {r.status_code}, byte-identical ({time.time() - t0:.1f}s incl. retries)")
    prov = {}
    for _ in range(40):
        prov = {p["provider"]: p for p in admin.req("GET", "/api/storage/providers").json()["providers"]}
        if prov["gcs"]["healthy"] is False:
            break
        time.sleep(0.5)
    table([[p["provider"], p["healthy"], p["state"], p["consecutive_failures"], p["injected"], p["last_error"] or ""]
           for p in prov.values()], ["provider", "healthy", "breaker", "failures", "injected", "last error"])
    check(prov["gcs"]["healthy"] is False and prov["gcs"]["injected"] is False,
          "health shows GCS down (a real outage, not an injected fault)")
    data2 = os.urandom(2 * 1024 * 1024 + 7)
    r = alice.req("POST", "/api/files", files={"file": ("during-outage.bin", data2, "application/octet-stream")})
    check(r.status_code == 201, f"upload during the outage -> {r.status_code}")
    d2 = alice.req("GET", f"/api/files/{r.json()['id']}/distribution").json()
    placed = sorted({rep["provider"] for c in d2["chunks"] for rep in c["replicas"]})
    check("gcs" not in placed, f"new chunks were written to {placed} only")

    # 14 --------------------------------------------------------------------
    step("Restart the emulator; provider health recovers")
    say(emu("start-one", "gcs").replace("\n", "\n    "))
    for _ in range(80):
        prov = {p["provider"]: p for p in admin.req("GET", "/api/storage/providers").json()["providers"]}
        if prov["gcs"]["healthy"]:
            break
        time.sleep(0.5)
    check(prov["gcs"]["healthy"] is True, f"GCS healthy again (state={prov['gcs']['state']})")
    v = alice.req("POST", f"/api/files/{fid}/verify").json()
    check(v["healthy"] is True, f"file verify after the outage: healthy={v['healthy']} summary={v['summary']}")

    # 15 --------------------------------------------------------------------
    step("The matching audit events (queried by auditor bob through the API; actors are pseudonyms)")
    types = ["auth.bootstrap_admin", "auth.register", "auth.login", "auth.mfa_enroll", "auth.mfa_activate",
             "admin.user.role",
             "file.upload", "file.download", "authz.decision", "storage.replica.corrupt", "file.verify",
             "file.repair", "chunk.repair", "audit.verify", "storage.provider.health", "chunk.distribute"]
    evs = bob.req("GET", "/api/audit/events", params={"limit": 1000, "order": "asc"}).json()["events"]
    shown = [e for e in evs if e["event_type"] in types and not (e["event_type"] == "authz.decision"
                                                                  and e["outcome"] == "success")]
    if len(shown) > 60:
        shown = [e for e in shown if e["event_type"] != "chunk.distribute"]
    table([[e["seq"], e["ts"][11:23], e["event_type"], e["outcome"], e["severity"], (e["actor"] or "-")[:12],
            e["actor_role"] or "-", (e["reason"] or "")[:40], e["source_net"] or ""] for e in shown],
          ["seq", "time", "event", "outcome", "severity", "actor", "role", "reason", "net"])
    check(any(e["event_type"] == "authz.decision" and e["outcome"] == "denied" for e in shown) and
          any(e["event_type"] == "storage.replica.corrupt" for e in shown) and
          any(e["event_type"] == "audit.verify" and e["severity"] == "critical" for e in shown) and
          any(e["event_type"] == "storage.provider.health" and e["outcome"] == "error" for e in shown),
          "denied access, corrupt replica, failed verification and provider outage are all on record")
    raw = b"".join(p.read_bytes() for p in DATA.glob("audit.db*"))
    secrets_used = (alice_pw, bob_pw, ADMIN_PW, FILENAME, alice.token, bob.token, admin.token,
                    admin.totp_secret, alice.totp_secret, bob.totp_secret)
    check(all(s.encode() not in raw for s in secrets_used) and MARKER not in raw,
          "audit DB bytes contain no password, token, TOTP seed, filename or file content")

    # 16 --------------------------------------------------------------------
    step("Summary")
    failed = [c for c in CHECKS if not c[2]]
    say(f"{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for s, what, _ in failed:
        say(f"FAILED in step {s}: {what}")
    return 0 if not failed else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["--wipe-buckets"]:
        import boto3
        from azure.storage.blob import BlobServiceClient
        from google.auth.credentials import AnonymousCredentials
        from google.cloud import storage as gcs

        bucket = os.environ["ZT_S3_BUCKET"]
        if not bucket.startswith("zt-demo-"):
            sys.exit("refusing to wipe a bucket that is not a per-run demo bucket")
        n = 0
        s3 = boto3.client("s3", endpoint_url=os.environ["ZT_S3_ENDPOINT_URL"], region_name=os.environ["ZT_S3_REGION"],
                          aws_access_key_id=os.environ["ZT_S3_ACCESS_KEY_ID"],
                          aws_secret_access_key=os.environ["ZT_S3_SECRET_ACCESS_KEY"])
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"]); n += 1
        az = BlobServiceClient.from_connection_string(os.environ["ZT_AZURE_CONNECTION_STRING"]) \
            .get_container_client(os.environ["ZT_AZURE_CONTAINER"])
        for b in list(az.list_blobs()):
            az.delete_blob(b.name); n += 1
        g = gcs.Client(project=os.environ["ZT_GCS_PROJECT"], credentials=AnonymousCredentials(),
                       client_options={"api_endpoint": os.environ["ZT_GCS_ENDPOINT_URL"]})
        for b in list(g.list_blobs(os.environ["ZT_GCS_BUCKET"])):
            b.delete(); n += 1
        print(f"[demo] removed {n} objects from the per-run demo buckets ({bucket})")
        sys.exit(0)
    try:
        sys.exit(main())
    except Exception as exc:          # keep secrets out of tracebacks: print the type and step only
        print(f"\nDEMO ABORTED in step {STEP[0]}: {type(exc).__name__}: {str(exc)[:200]}")
        sys.exit(2)
