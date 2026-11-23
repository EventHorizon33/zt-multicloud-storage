# Container deployment (optional)

> **Status: UNTESTED.** These files were written for the final submission but have **not** been built or
> run. In the development environment the Docker daemon could be started, but every base-image pull from
> Docker Hub (`python`, `node`, `nginxinc/nginx-unprivileged`) was refused by the environment's network
> egress policy, so no image could be built. The only check that was run is
> `docker compose config -q` (the compose file parses and validates). The supported and tested way to run the project is
> [`QUICKSTART.md`](../QUICKSTART.md) (no Docker; all results in the README come from that path).

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

Smoke test (what we would have run): sign in, enrol MFA, upload a file under **Files**, download it and
compare the SHA-256 shown by the UI, and check the chunk map under **Storage distribution**.

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

## Known gaps

* Untested (see the status note above). Expect small fixes on a first real build. Two likely ones: the
  owner of the Azurite volume when the container runs as `node`, and the permissions of the bind-mounted
  secret.
* Plain HTTP on localhost only; no TLS termination, no certificate management.
* Single backend instance (rate limits, lockout serialisation and the circuit breaker are per process).
* The emulators are not AWS, Azure or GCP. For real clouds remove the endpoint variables, give the backend
  least-privilege, bucket-scoped credentials per provider through a secret manager, and delete the
  emulator services.
