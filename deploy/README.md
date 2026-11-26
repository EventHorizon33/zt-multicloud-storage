# Container deployment (optional)

> **Status: built and smoke-tested once (2026-11-26), on one machine.** The compose stack was built and run on 2026-11-26: five containers healthy, a user registered, enrolled MFA, uploaded a 20 MiB file and a 300 MiB file (19 chunks of 16 MiB) through nginx, and downloaded both with identical SHA-256 (`deploy/smoke_test.py`, 12/12 checks, twice). The first run found a defect (the new
> `azurite-data` volume is owned by root, so Azurite, which runs as `node`, could not write its database); the `azurite-perms`
> one-shot service fixes it. An earlier attempt had been blocked because Docker Hub pulls were refused. Not covered: the browser suite
> against the containers, real clouds, TLS, and files above 300 MiB through nginx. Most results in the README come from the
> [`QUICKSTART.md`](../QUICKSTART.md) path (no Docker).

## What it starts

| Service | Image | Role | Network |
|---|---|---|---|
| `s3` | backend image, `moto_server` | S3 **emulator** (moto) | `backplane` (internal) |
| `azurite` | `mcr.microsoft.com/azure-storage/azurite` | Azure Blob **emulator** | `backplane` |
| `gcs` | backend image, `gcp-storage-emulator` | GCS **emulator** | `backplane` |
| `bucket-init` | backend image, `scripts/emulators/ensure_buckets.py` | one-shot: creates bucket/container on each emulator through the app's own adapters | `backplane` |
| `backend` | `deploy/Dockerfile.backend` | FastAPI/uvicorn on :8000, `ZT_ENV=production` | `backplane` + `edge` |
| `frontend` | `deploy/Dockerfile.frontend` | multi-stage Vite build → unprivileged nginx on :8080; serves the SPA and proxies `/api/` to the backend (same origin) | `edge`, published on `127.0.0.1:8080` |

moto and gcp-storage-emulator are already pinned in `backend/requirements.txt`, so they run from the
backend image; only Azurite needs its own image.

## Run

```bash
cd deploy
cp .env.example .env          # set ZT_BOOTSTRAP_ADMIN_PASSWORD (>= 12 chars, not common)
./make-secrets.sh             # writes secrets/kms_root_key (base64 of 32 random bytes)
docker compose up --build -d
docker compose ps             # all healthy, bucket-init exited 0
# UI: http://localhost:8080  -> sign in as admin, enrol TOTP under Account, sign in again with a code
docker compose down           # keep data;  docker compose down -v  deletes all volumes
```

Smoke test: `ZT_SMOKE_ADMIN_PASSWORD=<the admin password from .env> python deploy/smoke_test.py` (needs `httpx` and `pyotp`; set
`ZT_SMOKE_SIZE_MIB=300` for the large-file check). It checks the SPA, `/api/health` and `/metrics` through nginx, signs in, registers a user,
enrols TOTP, uploads a multi-chunk file, checks the chunk map and downloads the file, comparing SHA-256. By hand: sign in, enrol MFA,
upload a file under **Files**, compare the SHA-256 shown by the UI, and check **Storage distribution**.

## Security choices

* **Secrets.** The KMS root key is a Docker secret (`/run/secrets/kms_root_key` →
  `ZT_KMS_ROOT_KEY_FILE`); it is never in the image, the compose file or git (`deploy/secrets/` and
  `deploy/.env` are git-ignored). The bootstrap admin password and the optional `ZT_METRICS_TOKEN` come from
  `deploy/.env`. `ZT_ENV=production` (also the default) refuses to start without a root key, hides `/docs`,
  sends HSTS and refuses fault injection and insecure cookies. Compose bind-mounts file secrets with their
  host permissions, so `make-secrets.sh` makes the file world-readable (0444) for the container's uid 10001;
  keep `deploy/secrets/` itself on a host only you can log in to.
* **Non-root.** Backend and Python emulators run as uid 10001, nginx as uid 101, Azurite as its image's
  `node` user. `cap_drop: [ALL]` and `no-new-privileges` everywhere.
* **Read-only root filesystems** for every service; writable state only in named volumes (`/data`,
  emulator data) and `tmpfs` (`/tmp`, which also holds the backend's download spool, ADR-0005).
* **Networks.** The emulators sit on an `internal` network with no route to the host or the Internet; only
  nginx is published, and only on `127.0.0.1`. `/metrics` is not proxied (finding L5).
* **Client IP (ADR-0011).** nginx *replaces* `X-Forwarded-For` with the peer address; the backend uses
  `ZT_TRUST_FORWARDED_FOR=true`, `ZT_TRUSTED_PROXY_HOPS=1` and honours the header only from the `edge`
  subnet (`ZT_TRUSTED_PROXY_CIDRS`).
* **Cookies.** `ZT_COOKIE_SECURE=true`. Browsers accept `Secure` cookies on `http://localhost`; anywhere
  else terminate TLS in front of nginx.
* **Healthchecks** on every long-running service; the backend starts only after `bucket-init` succeeded,
  the frontend only after the backend is healthy.

## Chunk size and timeouts

The compose file sets `ZT_CHUNK_SIZE_BYTES=16777216` (16 MiB) and `ZT_STORAGE_TIMEOUT_SECONDS=30.0`. The
framework default is still 1 MiB, which the tests, the demo and the paper assume.

* **Why.** Each chunk costs two metadata commits, one audit event and a round-trip to each of two providers,
  whatever its size, while the cipher is only about 7 to 11% of the time. In our sweep (1 to 64 MiB chunks,
  5 MiB to 1 GiB files, local emulators, `scripts/bench/`), a 1 GiB upload took 39.3 s at 1 MiB and 11.8 s at
  16 MiB, and the download 12.2 s against 7.0 s. Throughput plateaus between 8 and 32 MiB, and 64 MiB was
  slower and used more memory.
* **Existing files stay readable.** Every file records its own chunk size in its sealed manifest, so files
  written at 1 MiB can be read after the change. Only new uploads use 16 MiB.
* **Timeout.** The provider deadline is a single value per operation, so it must exceed the time to move one
  chunk. 30 s allows about 0.6 MiB/s per replica for 16 MiB. A provider that hangs (rather than refusing
  connections) now takes up to 30 s per attempt to give up on, so failover is slower than with the 10 s default.
* **Memory.** The splitter holds up to two chunks per upload, so allow about 2 x 16 MiB per concurrent upload
  plus copies made during encryption.
* **Not measured.** Only local emulators were tested (no network latency), the chunk-size sweep stopped at
  1 GiB (the 16 MiB setting was later run at up to 10 GiB, see "Large files"), and the numbers drifted about
  10 to 19% during the sweep. Re-measure on the real target before relying on them.

## Large files (up to 10 GiB)

Three separate limits stop large files, and each has a decision recorded here (ADR-0012). The relationships between the compose file,
nginx and the application settings are checked by `backend/tests/unit/deploy/test_deployment_config.py`. The framework defaults are
unchanged (256 MiB upload cap, 512 MiB detector threshold); the compose file and `nginx.conf` set the values
below. To go back to the defaults, remove the two compose variables and restore `client_max_body_size 260m`.

| Limit | Default | This deployment | Why |
|---|---|---|---|
| Upload cap `ZT_MAX_UPLOAD_BYTES` | 256 MiB | 10 GiB | Target maximum file size. Larger bodies are refused with 413 before any data is read. |
| nginx `client_max_body_size` | 260m | 10250m | Must exceed the backend cap plus about 1 MiB of multipart overhead. |
| Bulk-download detector `ZT_DETECT_MAX_DOWNLOAD_BYTES_IN_WINDOW` | 512 MiB per 5 min | 20 GiB per 5 min | See below. |
| nginx `proxy_read_timeout` | 300s | 1800s | The backend sends nothing until the file is fetched and verified. |

* **Detector.** With the default, one legitimate download above 512 MiB counts as bulk exfiltration: it is
  refused (403, `download-rate-exceeded`), the user is blocked from all downloads for 10 minutes, and a CRITICAL
  audit event is written (confirmed by experiment). 20 GiB per window allows two 10 GiB downloads and blocks the
  third. **This weakens the volume limit about 40-fold against a stolen account.** The count limit (20
  downloads per 5 minutes) is unchanged. A size-aware detector would avoid the trade-off but is a security-logic
  change that needs its own review.
* **Spool.** Downloads are decrypted into a temporary file under `$ZT_DATA_DIR/tmp` (the `zt-data` volume),
  not the `/tmp` tmpfs. Keep at least 10 GiB free on that volume per concurrent download of a maximum-size file
  (50 GiB is a sensible minimum).
* **Measured** (local emulators, 16 MiB chunks, 30 s provider deadline, test-only settings; `scripts/bench/limits.py`):
  10 GiB uploaded in 140 s and downloaded in 92 s with the first byte after 56 s, byte-for-byte identical;
  server memory stayed at 350 to 380 MiB for 2, 5 and 10 GiB files. An upload that ran 384 s (longer than the
  5-minute access token) completed, and the expired token was then refused, as designed.
* **Not verified.** The Docker stack and `nginx.conf` have never been built or run, so none of the nginx
  values are tested. The web UI's upload of a multi-GiB file has not been tried in a browser. Real cloud providers
  were not used: a single request that runs for hours on a slow uplink is fragile, and a resumable upload API
  would be needed beyond a few GiB over wide-area links.

## Known gaps

* Smoke-tested once (see the status note above). The Azurite volume ownership was the defect that first build found; the
  permissions of the bind-mounted secret worked as documented (the backend read the 0444 file as uid 10001).
* Plain HTTP on localhost only; no TLS termination, no certificate management.
* Single backend instance (rate limits, lockout serialisation and the circuit breaker are per process).
* The emulators are not AWS, Azure or GCP. For real clouds remove the endpoint variables, give the backend
  least-privilege, bucket-scoped credentials per provider through a secret manager, and delete the
  emulator services.
