# REST API

Backend: FastAPI (`backend/app/main.py`, `uvicorn app.main:app`). Interactive docs at `/docs` (Swagger)
and `/redoc` (and `/openapi.json`) only when `ZT_ENV` is `development` or `test`; they are disabled in production.
`ZT_ENV` defaults to `production` (finding M4): development conveniences need it set explicitly.

All paths below are absolute. All request and response bodies are JSON (UTF-8) unless stated
otherwise. Timestamps are ISO-8601 UTC strings ending in `Z` (audit timestamps use the fixed
`YYYY-MM-DDTHH:MM:SS.ffffffZ` form). IDs (`user.id`, `file.id`, `session.id`) are 32 lowercase hex characters.

## Conventions

### Authentication

* **Access token**: `Authorization: Bearer <access_token>` on every endpoint marked *auth: bearer*.
  Tokens live `expires_in` seconds (default 300). On **every** request the server re-checks the token
  signature, expiry, the session row (revoked / idle / absolute expiry) and the user row (active, role,
  clearance, network allow list). Role changes, disablement and revocation apply on the next request.
* **Network allow list** (`allowed_cidrs`, set by an admin): enforced by the PDP on every PDP-gated route
  (`403 network-not-allowed`) **and** by the auth service itself: `login` and `refresh` from outside the
  list answer the generic `401` (audited with reason `network-not-allowed`, not counted towards lockout;
  a refused refresh does not consume the token), and `GET /api/auth/me`, the session list/revoke endpoints,
  password change and every MFA endpoint answer `403 network-not-allowed` (findings F2, L1). A refresh from
  outside the list is refused **before** the reuse check, so an outsider holding an already-used refresh
  token cannot trigger the reuse revocation of the owner's session (finding L2; audited `auth.refresh`
  failure, reason `network-not-allowed`, `details.reuse_suspected`).
* **Refresh token**: set by `login` / `refresh` as cookie `zt_refresh` (HttpOnly, `SameSite=Strict`,
  `Path=/api/auth`, `Secure` unless `ZT_COOKIE_SECURE=false`). The SPA never sees it; call
  `POST /api/auth/refresh` with `credentials: "include"` to obtain a new access token. Refresh tokens are
  single-use; replaying a used one revokes the whole session.
* **Restricted session**: when the policy setting `require_mfa_for_login` is on (the **default** since
  ADR-0010; `ZT_REQUIRE_MFA_FOR_LOGIN`) and the session has not passed a second factor, every PDP-gated
  endpoint returns `403` with reason `mfa-enrollment-required` except `security:read` / `policy:read`
  endpoints. Of `/api/auth/*` a restricted session may use only `me`, `logout`, `refresh` and MFA
  enrol/activate (with their own gating, below) -- `GET/DELETE /api/auth/sessions…` and
  `POST /api/auth/password` answer `403 mfa-required` (finding M5). An account **without a factor** is
  treated as restricted for these account-management endpoints even when `require_mfa_for_login` is off
  (obligation `enroll-mfa`). `GET /api/auth/me` reports `restricted: true`. A session becomes MFA-verified only through a login with `totp_code` or
  `POST /api/auth/mfa/verify`; **activating a factor does not verify the session it was started from**.
* **MFA enrolment** (ADR-0010, finding F1): a first factor may be enrolled by the account itself only
  (a) within `ZT_MFA_SELF_ENROLL_WINDOW_SECONDS` (default 24 h) of registration if the account never had
  a factor, or (b) by the bootstrap admin while no other active admin holds a factor. Otherwise
  `POST /api/auth/mfa/enroll` needs a single-use `enrollment_code` issued by an admin
  (`POST /api/admin/users/{id}/mfa-enrollment-code`), else `403 mfa-enrollment-requires-approval`.
  Replacing an existing factor needs `current_code` from it. Enrol → activate must happen within
  `ZT_MFA_PENDING_ENROLLMENT_TTL_SECONDS` (15 min).
* **Step-up MFA**: actions in `mfa_required_actions` (default `file:delete`, `file:share`, `user:manage`,
  `policy:write`, `kms:rotate`, `audit:retention`, `storage:admin`) and downloads of files classified
  `confidential` or above need a second factor verified within `mfa_step_up_max_age_seconds` (default 600).
  Otherwise `403` with `reasons` containing `mfa-required` or `mfa-stale` and `obligations: ["step-up-mfa"]`
  (plus `"enroll-mfa"` if the user has no MFA). Call `POST /api/auth/mfa/verify`, then retry.
  **Password change** needs the same fresh second factor (finding H1), see `POST /api/auth/password`.

### "Required action"

The *action* column names the policy action the PEP evaluates (`app/contracts.py: Action`). Every decision
is audited as `authz.decision`. Permission matrix: `backend/app/policy/NOTES.md`. Summary:

| Action | user | auditor | admin |
|---|---|---|---|
| file:create, file:list | ✔ | ✔ | ✔ |
| file:read-metadata | owner, grantee | owner, grantee | any file |
| file:read (download) | owner, grantee | owner, grantee | owner, grantee only |
| file:delete, file:share | owner | owner | owner only |
| file:verify, file:repair | owner | owner | any file |
| audit:read-own, dashboard:read, storage:read, policy:read, security:read | ✔ | ✔ | ✔ |
| audit:read-all, audit:verify, kms:read | – | ✔ | ✔ |
| user:list | – | – | ✔ |
| user:manage, policy:write, kms:rotate, storage:admin, audit:checkpoint, audit:retention | – | – | ✔ |

Auditors work with audit pseudonyms only: they hold no `user:list` (finding M1), so there is no user
directory that maps pseudonyms to accounts outside the audited `POST /api/admin/pseudonym-lookup`.

Clearance: reading or creating a file whose classification ranks above the user's clearance is denied
(`insufficient-clearance`). Ranks: `public` < `internal` < `confidential` < `restricted`; new users get
clearance `confidential`.

### Errors

Every error response has this body:

```json
{"error": "access-denied", "reasons": ["mfa-required"], "request_id": "9f1c...", "obligations": ["step-up-mfa"]}
```

`obligations` is present only when non-empty (policy denials). `reasons` are machine codes; messages are
never returned.

| HTTP | `error` | When |
|---|---|---|
| 400 | `bad-request` | malformed Content-Length |
| 400 | `bad-forwarded-for` | `ZT_TRUST_FORWARDED_FOR=true` and the `X-Forwarded-For` chain is malformed or shorter than `ZT_TRUSTED_PROXY_HOPS` (ADR-0011) |
| 400 | `bad-multipart` | upload body is not parseable `multipart/form-data` (finding I1) |
| 401 | `unauthenticated` | missing/invalid/expired token, revoked/expired session, disabled user. `reasons` is **always empty** except on `POST /api/auth/login`, where it may be `["mfa-required"]` (password correct, TOTP needed) or `["mfa-invalid"]`. Header `WWW-Authenticate: Bearer`. |
| 403 | `access-denied` | policy deny (`reasons` from the PDP, e.g. `mfa-required`, `mfa-stale`, `insufficient-clearance`, `admin-no-content-access`, `download-rate-exceeded`, `network-not-allowed`, `mfa-enrollment-required`, `default-deny`), wrong MFA code (`mfa-invalid`), wrong current password (`current-password-invalid`), MFA enrolment gating (`mfa-enrollment-requires-approval`, `mfa-enrollment-code-invalid`), network allow list on auth endpoints (`network-not-allowed`), `registration-disabled`, restricted session on account management (`mfa-required` + `enroll-mfa`/`step-up-mfa`), `pseudonym-key-rotation-disabled` |
| 404 | `not-found` | unknown route or resource. For files, **unknown IDs and IDs the caller may not access are indistinguishable** (both 404) for non-admins |
| 405 | `method-not-allowed` | |
| 409 | `conflict` | `mfa-already-enabled`, `mfa-not-enrolled`, `mfa-enrollment-expired`, `file-busy`, `file-not-available`, `cannot-modify-self`, `last-admin` (registration never answers `username-taken`: see register) |
| 409 | `integrity-failure` / `manifest-integrity-failure` / `chunk-integrity-failure` / `file-integrity-failure` | tampering detected (manifest MAC, metadata hash, key unwrap, every replica corrupt). **No file content is returned.** `reasons` e.g. `manifest-mac-invalid`, `metadata-hash-mismatch`, `key-unwrap-failed`, `all-replicas-corrupt` |
| 413 | `request-too-large` | JSON body > 64 KiB, upload > `ZT_MAX_UPLOAD_BYTES`, multipart part header over the parser limit (`multipart-limit-exceeded`) |
| 422 | `validation-failed` | request schema (`reasons` like `"username:string_pattern_mismatch"`; integer parameters such as `seq`, `from_seq`, `to_seq`, `offset` are bounded to 1/0..2^63-1, finding I2), password policy (`password-too-short`, `password-too-common`, `password-contains-username`, `password-unchanged`), `invalid-filename`, `invalid-classification`, `multipart-required`, `file-missing`, `share-target-invalid`, `invalid-cidr`, policy settings (`"<key>:<code>"`) |
| 429 | `rate-limited` | header `Retry-After: <seconds>`. Also for every bearer request from a client network that sent too many invalid tokens (finding M2) |
| 500 | `internal-error` | |
| 502 | `upload-failed` | not enough providers accepted a chunk (`storage-unavailable`); the file is `failed`, nothing is left on providers |
| 503 | `data-unavailable` | a chunk has no reachable replica (`data-unavailable`) |
| 503 | `audit-unavailable` | the audit log could not be written; the operation was not performed (fail closed) |
| 409 | `audit-integrity-failure` | retention refused because the audit chain does not verify |

### Common headers

Every response: `X-Request-ID` (**always generated by the server**, 32 hex; it is the audit `request_id`,
finding L8), `Content-Security-Policy: default-src 'none'; …`, `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`; in production also
`Strict-Transport-Security`. A client may send its own `X-Request-ID` (1–64 `[A-Za-z0-9._-]`, otherwise it
is dropped): it is echoed as `X-Client-Request-ID` and recorded as `details.client_request_id` on the
request's audit events, never as the request id. `/api/*` responses also send `Cache-Control: no-store`.
CORS: origins from `ZT_CORS_ORIGINS`, credentials allowed, exposed headers
`Content-Disposition, X-Request-ID, X-Client-Request-ID, X-Content-SHA256, Retry-After`.

### Client IP

The client IP (PDP allow list, rate-limit keys, audit `source_net`) is the TCP peer, unless
`ZT_TRUST_FORWARDED_FOR=true` (ADR-0011): then all `X-Forwarded-For` header lines are joined in order,
split on commas, and the entry `ZT_TRUSTED_PROXY_HOPS` (default 1) positions from the right is used.
Every entry must be an IP address (`a.b.c.d:port` and `[v6]:port` have the port stripped); otherwise the
request is refused with `400 bad-forwarded-for`. With `ZT_TRUSTED_PROXY_CIDRS` set the header is honoured
only when the TCP peer is one of those proxies.

### Rate limits (per process, token bucket, burst = per-minute value)

"Client network" = the IPv4 address, or the **/64** of an IPv6 address (finding L4: one IPv6 client
usually owns a whole /64).

| Scope | Key | Setting (default) |
|---|---|---|
| register | client network | `ZT_RATE_LIMIT_REGISTER_PER_MINUTE` (5) |
| login, refresh | client network | `ZT_RATE_LIMIT_LOGIN_PER_MINUTE` (10) |
| invalid bearer tokens (any bearer route) | client network | `ZT_RATE_LIMIT_INVALID_TOKEN_PER_MINUTE` (20) — only failed verifications spend; while empty, every bearer request from that network is answered 429 **before** any token verification (finding M2) |
| MFA enrol/activate/verify/disable, password change | user | `ZT_RATE_LIMIT_LOGIN_PER_MINUTE` (10) |
| upload | user | `ZT_RATE_LIMIT_UPLOAD_PER_MINUTE` (30) |
| download | user | `ZT_RATE_LIMIT_DOWNLOAD_PER_MINUTE` (60) |
| file verify + repair (shared) | user | `ZT_RATE_LIMIT_VERIFY_PER_MINUTE` (6) (finding L6) |
| audit export | user | `ZT_RATE_LIMIT_AUDIT_EXPORT_PER_MINUTE` (6) (finding L7) |

Rejections (`429`) are audited (finding F6): the first per (scope, key) per 60 s window as
`security.rate-limited` (outcome `denied`, severity `warning`, `details: {scope, count: 1, window_seconds,
kind: "first"}`, with the request id and client network; the actor for user-keyed scopes). Further 429s in
that window are only counted and written as one `kind: "summary"` event when the window is over.
Invalid-token failures (`auth.token`) are aggregated the same way per client network: the first per
60 s window is recorded with its reason, the rest as one summary (`reason: token-failures-aggregated`,
`details.count`).

### Shared object shapes

**User**
```json
{"id": "hex32", "username": "alice", "role": "user|auditor|admin",
 "clearance": "public|internal|confidential|restricted", "is_active": true, "mfa_enabled": false,
 "created_at": "2026-11-12T10:00:00.123456Z"}
```
Usernames are stored lower-case (`Alice` and `alice` are the same account); pattern `^[A-Za-z0-9_.-]{3,64}$`.

**Session**
```json
{"id": "hex32", "created_at": "…Z", "last_seen_at": "…Z", "expires_at": "…Z", "mfa_verified": false,
 "current": true}
```

**Token response** (login, refresh)
```json
{"access_token": "<JWS>", "token_type": "bearer", "expires_in": 300, "session_id": "hex32",
 "mfa_verified": false, "user": {User}}
```

**Me**
```json
{"user": {User}, "session": {Session}, "audit_pseudonym": "u_<32 hex>", "restricted": false,
 "mfa_fresh": false}
```
`mfa_fresh`: the session passed MFA within the step-up window (step-up actions will be allowed).

**File**
```json
{"id": "hex32", "filename": "report.pdf", "mime_type": "application/pdf", "size_bytes": 12345,
 "classification": "internal", "status": "pending|uploading|committed|failed|deleting|deleted",
 "chunk_count": 1, "chunk_size": 1048576, "created_at": "…Z", "committed_at": "…Z|null",
 "owner_id": "hex32", "owner_username": "alice", "is_owner": true, "shared_with_me": false,
 "failure_reason": null, "metadata_error": null}
```
* `filename` / `mime_type` are decrypted only for the owner or a grantee of a `committed` file; otherwise
  `null` (admin listings, failed files).
* `failure_reason` (failed uploads): `storage-unavailable`, `upload-too-large`, `client-aborted`,
  `interrupted`, `internal-error`, ….
* `metadata_error`: `"integrity-failure"` if the stored name blob or manifest failed verification
  (a critical audit event is written; the row is still listed).
* Only `status == "committed"` files can be downloaded, shared, verified or repaired.

**Audit event**
```json
{"seq": 42, "id": "hex32", "ts": "2026-11-12T10:00:00.123456Z", "event_type": "file.download",
 "action": "file:read", "outcome": "success|failure|denied|error", "severity": "info|warning|critical",
 "actor": "u_<32 hex>|null", "actor_role": "user|null", "resource_type": "file|null",
 "resource_id": "hex32|null", "reason": "code|null", "details": {…}, "request_id": "…|null",
 "source_net": "203.0.113.0/24|null", "prev_hash": "<64 hex>", "hash": "<64 hex>"}
```
`actor` is a keyed pseudonym of the user id (never a username). `details` holds only allow-listed keys.

**Provider health row**
```json
{"provider": "aws-s3", "kind": "s3", "healthy": true, "state": "closed|open|half-open",
 "latency_ms": 3.2, "consecutive_failures": 0, "last_checked": "…+00:00|null", "last_error": null,
 "total_successes": 10, "total_failures": 0, "injected": false, "fault_mode": "none|null"}
```
`healthy` is `null` until the provider was first observed. `injected: true` marks a demo fault (never a real outage).

---

## Auth — `/api/auth`

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| POST | `/api/auth/register` | none (rate-limited) | `{"username": str, "password": str(≤256)}` | **202** `{"status": "accepted"}` whether or not the account was created (F3: no username enumeration; an existing name is not changed and is audited internally as `auth.register` failure `username-taken`). 422 invalid username / password policy (independent of whether the name exists). 403 `registration-disabled` when `ZT_ALLOW_SELF_REGISTRATION=false` |
| POST | `/api/auth/login` | none (rate-limited) | `{"username", "password", "totp_code"?: "123456"}` | **200** Token response + `Set-Cookie: zt_refresh` |
| POST | `/api/auth/refresh` | cookie `zt_refresh` | – | **200** Token response + new cookie. 401 clears the cookie |
| POST | `/api/auth/logout` | bearer | – | **204**, cookie cleared, session revoked |
| GET | `/api/auth/me` | bearer | – | **200** Me. 403 `network-not-allowed` (L1) |
| GET | `/api/auth/sessions` | bearer, **not restricted** | – | **200** `[Session]` (live sessions, newest first). 403 `mfa-required` for a restricted session (M5; obligation `enroll-mfa` without a factor, `step-up-mfa` with one), 403 `network-not-allowed` (L1) |
| DELETE | `/api/auth/sessions/{session_id}` | bearer, **not restricted** | – | **204**; 404 if not one of the caller's live sessions. 403 as for the list |
| POST | `/api/auth/mfa/enroll` | bearer | optional `{"enrollment_code"?: "XXXX-XXXX-XXXX-XXXX", "current_code"?: "123456"}` | **200** `{"secret": "BASE32", "otpauth_uri": "otpauth://totp/…"}` (shown once). 403 `mfa-enrollment-requires-approval` (outside the self-enrolment window: needs `enrollment_code`), 403 `mfa-enrollment-code-invalid`, 409 `mfa-already-enabled` (a factor exists and no `current_code`), 403 `mfa-invalid` (wrong `current_code`), 403 `network-not-allowed`. Audited `auth.mfa_enroll` (`details.method`: `tofu`, `bootstrap`, `admin-code`, `rotation`) |
| POST | `/api/auth/mfa/activate` | bearer | `{"code": "123456"}` | **200** Me (MFA enabled). **This session is not marked MFA-verified and no other session is revoked**: sign in again with `totp_code` (or `mfa/verify`) to get an MFA-verified session. Audited `auth.mfa_activate` at `warning`, reason `new-factor`. 403 `mfa-invalid`, 409 `mfa-not-enrolled` / `mfa-enrollment-expired`, 403 `network-not-allowed` |
| POST | `/api/auth/mfa/verify` | bearer | `{"code"}` | **200** Me (`mfa_fresh: true`). 403 `mfa-invalid`, 409 `mfa-not-enrolled`, 403 `network-not-allowed` |
| POST | `/api/auth/mfa/disable` | bearer | `{"code"}` | **200** Me (`user.mfa_enabled: false`; re-enrolling later needs an admin enrolment code). 403 `mfa-invalid`, 403 `network-not-allowed` |
| POST | `/api/auth/password` | bearer + **fresh MFA** (H1) | `{"current_password", "new_password"}` | **200** `{"sessions_revoked": n}`. Other sessions are revoked, **except** sessions that verified the second factor more recently than the caller's session (never any MFA-verified session if the caller's is not MFA-verified); audited with `details.sessions_revoked` / `sessions_kept`. 403 `mfa-required` / `mfa-stale` + `step-up-mfa` (factor not verified within `mfa_step_up_max_age_seconds`: step up and retry), 403 `mfa-required` + `enroll-mfa` (account without a factor: refused), 403 `current-password-invalid`, 403 `network-not-allowed`, 422 password policy |

Login notes: wrong username, wrong password, locked and disabled accounts all return the same
`401 {"reasons": []}`. Only after a correct password does the response say `mfa-required` (send again with
`totp_code`) or `mfa-invalid`. Failed logins count towards lockout (`ZT_MAX_FAILED_LOGINS`) and feed the
credential-stuffing detector. A login from outside the account's network allow list gets the same generic
401 before the password is even checked (audited `network-not-allowed`; it does not count towards lockout).

## Files — `/api/files`

| Method | Path | Auth / action | Request | Response |
|---|---|---|---|---|
| POST | `/api/files` | bearer; `file:create` (classification checked against clearance) | `multipart/form-data`: optional text field `classification` **before** the file part, then exactly one file part named `file` (its filename and Content-Type are stored encrypted). `classification` may instead be a query parameter `?classification=`. Default `internal`. | **201** File (`status: "committed"`) |
| GET | `/api/files` | bearer; `file:list` (+ per-row `file:read-metadata`) | – | **200** `{"files": [File], "total": n}`: own files in any status except deleted, plus committed files shared with the caller |
| GET | `/api/files/{id}` | bearer; `file:read-metadata` | – | **200** File |
| GET | `/api/files/{id}/download` | bearer; `file:read` (+ download-anomaly signals) | – | **200** `application/octet-stream` body; headers `Content-Disposition: attachment; filename="<ascii>"; filename*=UTF-8''<pct-encoded>`, `Content-Length`, `X-Content-SHA256: <hex sha256 of plaintext>`. Errors: 409 integrity (no body content), 503 `data-unavailable`, 403 `download-rate-exceeded` |
| DELETE | `/api/files/{id}` | bearer; `file:delete` (**fresh MFA**) | – | **200** `{"file_id", "status": "deleted", "leftover_replicas": n}` (wrapped key destroyed even if `leftover_replicas > 0`; leftovers are retried in the background). 409 `file-busy` |
| GET | `/api/files/{id}/shares` | bearer; `file:read-metadata`, owner only | – | **200** `{"shares": [{"username", "created_at"}]}`; 403 `not-owner` for grantees |
| POST | `/api/files/{id}/shares` | bearer; `file:share` (**fresh MFA**) | `{"username": str}` | **201** `{"file_id", "username", "created_at"}` (idempotent). 422 `share-target-invalid` (unknown, disabled, or yourself: one code for all) |
| DELETE | `/api/files/{id}/shares/{username}` | bearer; `file:share` | – | **204**; 404 `share-not-found` |
| POST | `/api/files/{id}/verify` | bearer; `file:verify` (owner; admin any); rate limit `verify` (L6) | – | **200** `{"file_id", "healthy": bool, "recoverable": bool, "summary": {"ok", "corrupt", "missing", "unavailable"}, "chunks": [{"index", "chunk_id", "replicas": [{"provider", "result": "ok|corrupt|missing|unavailable"}]}]}`. Reads ciphertext only; no plaintext. |
| POST | `/api/files/{id}/repair` | bearer; `file:repair` (owner; admin any); same `verify` budget | – | **200** `{"file_id", "ok": bool, "repaired_chunks": [index], "unrepairable_chunks": [index]}` |
| GET | `/api/files/{id}/distribution` | bearer; `file:read-metadata` | – | **200** `{"file_id", "status", "chunk_count", "replication_factor", "providers": {"<provider>": stored_replica_count}, "chunks": [{"index", "chunk_id", "ciphertext_size", "ciphertext_sha256", "replicas": [{"provider", "status": "pending|stored|failed|missing|corrupt|deleted", "stored_at", "last_verified_at"}]}]}` (replica `failed` = an object we could not delete, retried) |
| GET | `/api/admin/files?limit=100&offset=0` | bearer; `file:list` + per-row `file:read-metadata` | – | **200** `{"files": [File with filename/mime_type null], "total", "limit", "offset", "scope": "all|own"}`. Admins see every non-deleted file's metadata (never names or content); other roles only their own |

Upload limits: `ZT_MAX_UPLOAD_BYTES` (default 256 MiB; the container deployment sets 10 GiB) → 413. A download larger than the
bulk-download detector's whole byte budget (`ZT_DETECT_MAX_DOWNLOAD_BYTES_IN_WINDOW`, default 512 MiB) is itself refused with 403
`download-rate-exceeded`, and the user is blocked for 10 minutes (ADR-0012). Filenames: last path component, control
characters removed, 1–255 characters; they are never used as paths. A failed upload returns 502 (or
413/422), the file becomes `failed` and its stored chunks are deleted.

## Storage — `/api/storage`

| Method | Path | Auth / action | Response |
|---|---|---|---|
| GET | `/api/storage/providers` | `storage:read` | `{"providers": [Provider health row], "replication_factor": 2, "min_write_replicas": 2, "fault_injection_enabled": false}` |
| GET | `/api/storage/distribution` | `storage:read` | `{"scope": "all|own", "files": n, "bytes": n, "chunks": n, "files_by_status": {"pending": n, "uploading": n, "committed": n, "failed": n, "deleting": n, "deleted": n}, "distribution": {"<provider>": {"replicas": n, "bytes": ciphertext_bytes, "by_status": {"stored": n, …}}}}` (committed files only; `scope` is `all` for auditor/admin, `own` for users) |
| GET | `/api/storage/metrics` | `storage:read` | `{"counters": {provider: {op: {"attempts", "successes", "failures", "retries", "bytes"}}}, "latency": {provider: {op: {"count", "sum_seconds", "buckets": {"0.005": n, …, "+Inf": n}}}}}` |
| GET | `/api/storage/faults` | `storage:admin` (**fresh MFA**) — only if `ZT_ENABLE_FAULT_INJECTION=true` | `{"faults": [{"provider", "mode", "params", "remaining_failures", "injected", "fault_injection_enabled", "injected_failures_total"}]}` |
| PUT | `/api/storage/faults/{provider}` | same | body `{"mode": "none|unavailable|timeout|corrupt-reads|fail-n|drop-writes|slow", "delay"?: 0–30, "n"?: 1–1000}` → the provider's fault status object. Audited `storage.fault.set` |
| DELETE | `/api/storage/faults/{provider}` | same | clears the fault; same response |

## Audit — `/api/audit`

Callers with `audit:read-all` (auditor, admin) query all events; everyone else gets `audit:read-own`
and the server forces `actor IN (<every pseudonym the caller has had>)` -- one per retained version of the
pseudonym key, so an out-of-band key rotation does not hide a user's history (finding M3); the `actor`
filter is ignored for them.

| Method | Path | Auth / action | Request | Response |
|---|---|---|---|---|
| GET | `/api/audit/events` | `audit:read-all` or `audit:read-own` | query: `actor`, `event_type` (exact, or prefix ending in `.` or `*`, e.g. `file.*`), `action`, `resource_id`, `resource_type`, `outcome`, `severity`, `min_severity`, `from`, `to` (ISO; from inclusive, to exclusive), `request_id`, `limit` (1–1000, default 50), `offset`, `order` (`desc`/`asc`) | `{"events": [Audit event], "total": n, "limit", "offset", "scope": "all|own"}` |
| GET | `/api/audit/events/{seq}` (1 ≤ seq ≤ 2^63-1) | same | – | Audit event; 404 if absent or not the caller's (own scope) |
| GET | `/api/audit/stats?since=` | `audit:read-all` | – | `{"since", "total", "by_outcome": {"success", "failure", "denied", "error"}, "by_severity": {"info", "warning", "critical"}, "by_event_prefix": {"auth": n, …}, "by_event_type": {…}, "first_seq", "last_seq"}` |
| POST | `/api/audit/verify` | `audit:verify` | optional `{"from_seq"?, "to_seq"?, "check_anchors"?: true}` | `{"ok", "events_checked", "first_seq", "last_seq", "head_hash", "checkpoints_checked", "anchors_checked", "findings": [{"type", "seq", "detail"}], "findings_truncated", "duration_ms"}` (finding types: `backend/app/audit/NOTES.md`) |
| POST | `/api/audit/checkpoints` | `audit:checkpoint` | – | **201** Checkpoint `{"id", "seq", "head_hash", "ts", "kind": "manual", "key_id", "key_version", "signature", "event_count", "first_seq", "anchors": {"<provider>": bool}}` |
| GET | `/api/audit/checkpoints?limit=100` | `audit:verify` | – | `{"checkpoints": [Checkpoint]}` newest first |
| POST | `/api/audit/retention` | `audit:retention` (**fresh MFA**) | – | `{"deleted", "kept", "new_first_seq", "checkpoint_seq"}`; 409 `integrity-failure` if the chain does not verify |
| GET | `/api/audit/export?from_seq=&to_seq=` | `audit:read-all` / `audit:read-own`; rate limit `audit-export` (L7) | – | `application/x-ndjson`, one canonical JSON record per line (as hashed, `details` as a JSON string, plus `hash`); own scope is filtered **in the SQL query** (`actor IN (...)`), so only the caller's rows are read |

## Security — `/api/security`

| Method | Path | Auth / action | Request | Response |
|---|---|---|---|---|
| GET | `/api/security/events?limit=50&critical_limit=50` | `security:read` | – | `{"events": [Audit event], "critical": [Audit event], "scope": "all|own"}` — `events`: all: severity ≥ warning or outcome denied/failure; own: the caller's events with severity ≥ warning. `critical`: the newest `critical_limit` (1–500) **critical** events, selected separately so a flood of lower-severity events cannot push a critical alert out (finding M2) |
| GET | `/api/security/policies` | `policy:read` | – | `{"rules": [{"id", "description", "effect": "allow|deny", "stage": "guard|constraint|allow", "actions": [..] or "*", "roles": [..], "condition", "reason"}], "config": PolicyConfig, "version": n, "ignored_keys": []}` |
| GET | `/api/security/policy-settings` | `policy:read` | – | `{"config": PolicyConfig, "defaults": PolicyConfig, "version": n, "ignored_keys": []}` |
| PUT | `/api/security/policy-settings` | `policy:write` (**fresh MFA**, always) | `{"changes": {"<key>": value}}` | same as GET. Audited `policy.change` |
| GET | `/api/security/anomaly-blocks` | `security:read` | – | `{"blocks": [{"blocked_until", "reason": "bulk-download", "actor": "u_…", "user_id"?, "username"?}], "scope": "all|own"}` (`user_id`/`username` for admins and for the caller's own block) |
| DELETE | `/api/security/anomaly-blocks/{user_id}` | `user:manage` (**fresh MFA**) | – | **204**; 404 if no block. Audited `security.block.lift` |

`PolicyConfig`:
```json
{"mfa_required_actions": ["audit:retention", "file:delete", …], "mfa_required_classification": "confidential",
 "mfa_step_up_max_age_seconds": 600, "max_session_age_seconds": 43200, "require_mfa_for_login": true,
 "max_downloads_in_window": 20, "max_download_bytes_in_window": 536870912, "window_seconds": 300,
 "block_seconds": 600}
```
Validation (422 reasons `"<key>:<code>"`): unknown keys, wrong types, ranges (step-up 30 s–24 h,
session 5 min–30 d, downloads ≥ 1, window 10 s–7 d, block 0–30 d); `policy:write` can never be removed
from `mfa_required_actions`.

## Admin — `/api/admin`

| Method | Path | Auth / action | Request | Response |
|---|---|---|---|---|
| GET | `/api/admin/users` | `user:list` (**admin only**; auditors get 403 `default-deny`, finding M1) | – | `{"users": [AdminUser]}` (no audit pseudonyms) |
| PUT | `/api/admin/users/{id}/role` | `user:manage` (**fresh MFA**) | `{"role": "user|auditor|admin"}` | AdminUser. 409 `cannot-modify-self`, `last-admin` |
| PUT | `/api/admin/users/{id}/clearance` | `user:manage` | `{"clearance": "public|internal|confidential|restricted"}` | AdminUser |
| POST | `/api/admin/users/{id}/disable` | `user:manage` | – | AdminUser (`is_active: false`; all sessions revoked) |
| POST | `/api/admin/users/{id}/enable` | `user:manage` | – | AdminUser |
| PUT | `/api/admin/users/{id}/allowed-cidrs` | `user:manage` | `{"cidrs": ["10.0.0.0/8", "2001:db8::/32"]}` (≤ 32; `[]` = no restriction) | AdminUser |
| POST | `/api/admin/users/{id}/revoke-sessions` | `user:manage` | – | `{"sessions_revoked": n}` |
| POST | `/api/admin/users/{id}/mfa-enrollment-code` | `user:manage` + admin MFA verified within the step-up window (enforced even if `user:manage` is removed from `mfa_required_actions`) | – | `{"user_id", "enrollment_code": "XXXX-XXXX-XXXX-XXXX", "expires_at", "single_use": true}`. 80-bit code, shown once, stored only as a keyed HMAC bound to the user, valid `ZT_MFA_ENROLLMENT_CODE_TTL_SECONDS` (24 h); issuing a new one revokes the previous unused one. Audited `admin.user.mfa_enrollment_code` (warning). 409 `cannot-modify-self`, 409 `mfa-already-enabled` (reset the factor first) |
| POST | `/api/admin/users/{id}/mfa-reset` | `user:manage` + fresh admin MFA (as above) | – | AdminUser + `"sessions_revoked": n`. Removes the factor and any pending enrolment, revokes every session of the user; the user then needs an enrolment code to enrol again. Audited `admin.user.mfa_reset` (warning). 409 `cannot-modify-self` |
| GET | `/api/admin/kms/keys` | `kms:read` (auditor, admin) | – | `{"keys": [{"purpose", "key_id", "version", "algorithm", "created_at", "state": "active|decrypt-only|retired"}]}` (metadata only) |
| POST | `/api/admin/kms/rotate` | `kms:rotate` (**fresh MFA**) | `{"purpose": "file-dek-wrap|secret-encryption|token-signing|audit-signing|audit-pseudonym|lookup-hmac"}` | `{"purpose", "key_id", "version", "files_rewrapped", "rewrap_failures"}`. Rotating `file-dek-wrap` re-wraps every live file key (no chunk re-encryption). Rotating `lookup-hmac` invalidates outstanding refresh tokens. `audit-pseudonym` is **refused**: 403 `pseudonym-key-rotation-disabled`, audited `admin.kms.rotate` denied (finding M3; an offline, two-person operation, ADR-0007) |
| POST | `/api/admin/pseudonym-lookup` | `user:manage` (**fresh MFA**) | `{"pseudonym": "u_<32 hex>"}` | `{"pseudonym", "user": {"id", "username", "role"}}`; 404 if none. Matches every retained version of the pseudonym key. Always audited `audit.reidentify`. **The only API path that maps a pseudonym to an account** |

`AdminUser`:
```json
{"id", "username", "role", "clearance", "is_active", "mfa_enabled", "allowed_cidrs": [..],
 "created_at", "locked_until": "…Z|null", "active_sessions": n}
```
There is no admin route that returns another user's file content, filenames, or key material.

## Dashboard, health, metrics

| Method | Path | Auth / action | Response |
|---|---|---|---|
| GET | `/api/dashboard` | bearer; `dashboard:read` | see below |
| GET | `/api/health` | none | `{"status": "ok|degraded", "database": bool}` |
| GET | `/metrics` | `Authorization: Bearer <ZT_METRICS_TOKEN>` (scrape token, ≥ 32 chars, constant-time compared) **or** bearer **admin** access token (`storage:read`). No peer address is trusted, loopback included (finding L5) | Prometheus text format: `zt_storage_*` (per provider/op counters and latency histogram), `zt_files_committed`, `zt_bytes_committed`, `zt_files_by_status{status}`, `zt_replicas_stored{provider}`, `zt_provider_healthy{provider}`, `zt_audit_events{outcome}`, `zt_http_responses_total{status}` |

Dashboard response (`scope` = `all` for auditor/admin, `own` for users; every number is computed from
the metadata DB, the audit DB and the health monitor at request time):
```json
{"scope": "own", "generated_at": "…Z",
 "files": {"count": 3, "bytes": 1234, "chunks": 4,
           "by_status": {"pending": 0, "uploading": 0, "committed": 3, "failed": 1, "deleting": 0, "deleted": 2}},
 "distribution": {"aws-s3": {"replicas": 3, "bytes": 900, "by_status": {"stored": 3}}, "azure-blob": {…}, "gcs": {…}},
 "operations": {"by_outcome": {"success": 40, "failure": 1, "denied": 2, "error": 0}, "total": 43,
                "by_event_prefix": {"auth": 10, …} | null},
 "recent_security_events": [Audit event],
 "providers": [Provider health row], "providers_available": 3, "providers_total": 3}
```
`files.count/bytes/chunks` and `distribution` count committed files only. `operations` comes from the
audit log (own scope: the caller's own events; `by_event_prefix` is `null`).
