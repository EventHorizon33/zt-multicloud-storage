# app/api — REST API (Phase 6)

The endpoint reference (paths, auth, required action, exact request/response shapes, errors) is
**`docs/API.md`**. FastAPI's `/docs`, `/redoc` and `/openapi.json` are served only when `ZT_ENV` is not
`production`; `ZT_ENV` defaults to `production` (review M4).

## Entry points

```python
from app.main import create_app
app = create_app(settings: Settings | None = None, *, container: Container | None = None, **container_kwargs)
# container_kwargs go to Container.build: clock=, providers=, password_hasher=, kms=, background=, ...
```
`uvicorn app.main:app` — the module attribute `app` is created lazily (PEP 562 `__getattr__`), so importing
`app.main` needs no configuration. Lifespan: `container.start()` / `container.stop()`.
Dev server: `scripts/run-dev.sh` (emulators, dev KMS root key file, uvicorn on 127.0.0.1:8000, optional
bootstrap admin from `ZT_BOOTSTRAP_ADMIN_USERNAME/PASSWORD`). All variables: `backend/.env.example`.

## Files

| File | Content |
|---|---|
| `deps.py` | `get_db` (session per request), `get_caller` → `Caller(container, db, principal, context)`: bearer token → invalid-token gate (M2: per client network, `ZT_RATE_LIMIT_INVALID_TOKEN_PER_MINUTE`; 429 before any verification once the bucket is empty; only failures spend) → `AuthService.authenticate_request` (token + DB re-read of session and user every call) → `bind_actor` into the ambient audit context (F5) → `RequestContext(request_id, client_ip, clock())`; `Caller.enforce/check` = PEP; `rate_limit()` (429s go to `RateLimitAuditor`, F6) |
| `middleware.py` | one pure-ASGI middleware: ambient audit context per request (`app.audit.context.begin_request/end_request`, F5), request id (always generated; a valid client `X-Request-ID` becomes `client_request_id`: `X-Client-Request-ID` + audit `details.client_request_id`, L8), client IP (ADR-0011: if `trust_forwarded_for`, all `X-Forwarded-For` lines joined, entry `trusted_proxy_hops` from the right, optional `trusted_proxy_cidrs`; malformed → 400 `bad-forwarded-for`, H2), body caps (64 KiB JSON, `max_upload_bytes + 1 MiB` for `POST /api/files`, declared and streamed), security headers, `Cache-Control: no-store` on `/api/*` and `/metrics`, JSON access log (method, route template, status, duration, request id), response counters |
| `errors.py` | `{error, reasons, request_id[, obligations]}` for `AppError`, validation, HTTP and unhandled errors; 401 reasons stripped except login's `mfa-required`/`mfa-invalid`; `Retry-After` on 429; `upload-too-large` → 413 |
| `logging_setup.py` | JSON log formatter + regex redaction (JWTs, Bearer/Basic credentials, `password=`/`token=`/`code=`… assignments, refresh cookie); exceptions logged as type + file:line only; uvicorn access log disabled |
| `schemas.py` | Pydantic request models (`extra="forbid"`, bounded strings/lists) and auth response models |
| `upload.py` | `StreamingMultipart`: incremental `python_multipart` parser (parse errors → 400 `bad-multipart`, exceeded parser limits → 413, I1); the file part is pulled by the sync `FileService.upload` in a worker thread via `anyio.from_thread.run` — no temp file, bounded memory |
| `routes_auth.py` | `/api/auth/*` (register → uniform 202 (F3), login, refresh cookie, logout, me, sessions, MFA enrol (optional `enrollment_code`/`current_code`)/activate/verify/disable, password). The allow list (F2; also on `/me` and sessions, L1), MFA enrolment gating (F1), restricted-session gate on session list/revoke and password change (M5) and fresh MFA for password change (H1) are enforced through `AuthService`. IP-keyed limits use `ratelimit.client_network_key` (IPv6 /64, L4) |
| `routes_files.py` | `/api/files/*`, `/api/admin/files`; RFC 6266 `Content-Disposition` with ASCII fallback + `filename*`; verify/repair share the per-user `verify` rate limit (L6) |
| `routes_storage.py` | `/api/storage/{providers,distribution,metrics}`; `fault_router` (`/api/storage/faults`) included only when `enable_fault_injection` and not production |
| `routes_audit.py` | `/api/audit/*`; `audit_scope()` forces the caller's pseudonyms (every key version, M3) unless `audit:read-all` passes; own export filtered in SQL and rate limited (L7); `seq`/`from_seq`/`to_seq`/`offset` bounded to 2^63-1 (I2) |
| `routes_security.py` | `/api/security/*` (events + separate `critical` list (M2), policies, policy settings, anomaly blocks) |
| `routes_admin.py` | `/api/admin/*` over `app.admin.AdminService`, incl. `users/{id}/mfa-enrollment-code` and `users/{id}/mfa-reset` (`user:manage` + fresh admin MFA enforced in `AdminService` independently of the runtime policy) |
| `routes_dashboard.py` | `/api/dashboard`, `/api/health`, `/metrics` (`ZT_METRICS_TOKEN` bearer, constant-time compare, or an authenticated admin through the PEP; no peer-based trust, L5) |

## Integration items (from the subsystem reports) and where they are handled

1. Audit allow-list: `app/container.py: EXTRA_AUDIT_DETAILS`; `policy.change` flattened by
   `_PolicyAuditAdapter`. Test: `test_app_audit_detection.py::test_no_audit_detail_dropped_across_subsystems_and_chain_verifies`
   (events from auth, policy, storage orchestrator + health monitor, files, detection, admin, audit; asserts
   no `_dropped` and the specific keys survive).
2. Usernames: already lower-cased by `AuthService` with a functional unique index in `models.py`
   (the auth NOTES limitation was stale and is corrected). Tests: concurrent `Alice/alice/ALICE/aLiCe`
   registration → four identical 202s (F3) and exactly one account (three `username-taken` audit
   failures); direct `CAROL` insert after `carol` → `IntegrityError`.
3. Restricted sessions: `/api/auth/*` uses only `get_caller` (no PEP). Test: `test_restricted_session_can_enrol_mfa`,
   `test_default_policy_requires_mfa_and_activation_needs_a_new_login` (`require_mfa_for_login` is on by default).
4. `file:create` gets `Resource(classification=...)`; default `internal`; invalid → 422; above clearance → 403.
5. `audit:read-own`: `routes_audit.audit_scope` (search, event by seq, export). Test: `test_audit_scope_own_vs_all`.
6. Verify-then-release with spool: `FileService.download` + `routes_files.download_file`. Test:
   `test_large_download_spools_to_unlinked_tempfile`, `test_partially_corrupt_last_chunk_never_partially_delivered`.
7. `enc_metadata_sha256` checked before decrypting metadata: `FileService._metadata`. Test:
   `test_enc_metadata_hash_checked_before_decrypt`.
8. Anchor store = orchestrator via `OrchestratorAnchorStore`. Test: `test_checkpoints_are_anchored_on_every_provider`.

## Limitations
* Rate limiting, auth-failure detection and the circuit breaker are per process (single instance assumed).
* `/metrics` trusts no peer address (review L5; it used to trust loopback, which behind a same-host proxy is
  every client). Scrapers send `Authorization: Bearer $ZT_METRICS_TOKEN`; without the setting only an admin
  access token works.
* While a client network is over the invalid-token limit, every bearer request from it gets 429, including
  valid ones from other users behind the same NAT / IPv6 /64 (bucket refills at limit/60 per second).
* Upload form: `classification` must come before the file part (or as a query parameter); later text
  fields are ignored. Only one file per request.
* The download is buffered server-side before the first byte (ADR-0005), so time-to-first-byte grows with
  file size.
* No CSRF token on `/api/auth/refresh`; protection relies on the `SameSite=Strict` cookie scoped to
  `/api/auth` (and CORS with credentials only for configured origins).
* Responses are plain dicts for most routes (shapes are documented in `docs/API.md`, not all as Pydantic
  response models), so `/docs` shows request schemas exactly but some response schemas only generically.
* TLS is not handled by the app (terminate in front of it); HSTS is sent only when `ZT_ENV=production`
  (the default).

## Tests
External-review regression tests (H1, H2, M1–M5, L1–L8, I1, I2): `tests/review/` (see
`docs/SECURITY_TESTING.md`, "Independent security review", section 4a).
```
cd backend && .venv/bin/python -m pytest tests/integration/app -q -rs        # emulators running
cd backend && .venv/bin/python -m pytest -q -rs                               # whole suite
```
Results of the last full run (2026-11-23, `1236 passed`) are in `docs/SECURITY_TESTING.md` section 3 and `docs/FINAL_REPORT.md`.
