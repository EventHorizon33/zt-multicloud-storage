# Web UI (Phase 7)

React 19 + Vite + TypeScript single-page console for the zero-trust multi-cloud chunked storage
backend. It is built strictly against `docs/API.md`; every number, list and event on screen comes from a
live API call. When an endpoint returns nothing the screen says "No data yet" (or a specific empty
message), never sample data.

Runtime dependencies: `react`, `react-dom`, `react-router-dom`, `qrcode` (renders the TOTP enrolment URI
locally as an SVG), and two self-hosted font packages (`@fontsource/atkinson-hyperlegible`,
`@fontsource/ibm-plex-mono`, Latin subsets). Charts are hand-rolled bars. No analytics, no CDN, no secrets in
the bundle.

## Setup and development

```bash
# 1. backend + storage emulators (127.0.0.1:8000). Optional bootstrap admin:
ZT_BOOTSTRAP_ADMIN_USERNAME=admin ZT_BOOTSTRAP_ADMIN_PASSWORD='<12+ chars, not common>' scripts/run-dev.sh

# 2. UI dev server (127.0.0.1:5173)
cd frontend
npm install
npm run dev
```

`vite.config.ts` proxies `/api` and `/metrics` to `http://127.0.0.1:8000` (override with
`ZT_BACKEND_URL`). The SPA and the API therefore share one origin, which is what makes the refresh cookie
(`zt_refresh`, `HttpOnly`, `SameSite=Strict`, `Path=/api/auth`) work without CORS. `run-dev.sh` sets
`ZT_COOKIE_SECURE=false` because the dev stack is plain HTTP.

## Build and production serving

```bash
npm run build      # tsc -b (type check, zero errors required) + vite build -> dist/
npm run preview    # serves dist/ on 127.0.0.1:4173 with the same /api and /metrics proxy
```

Any static server works if it (a) serves `dist/`, (b) falls back to `index.html` for unknown paths
(client-side routes such as `/files`, `/audit`), and (c) proxies `/api/` (and optionally `/metrics`) to the
backend on the same origin. nginx example:

```nginx
location /api/    { proxy_pass http://127.0.0.1:8000; proxy_set_header X-Forwarded-For $remote_addr; }
location /metrics { proxy_pass http://127.0.0.1:8000; }   # or block it, see backend/app/api/NOTES.md
location /        { root /srv/zt-ui/dist; try_files $uri /index.html; }
```

Behind a proxy set `ZT_TRUST_FORWARDED_FOR=true` and `ZT_TRUSTED_PROXY_HOPS` (the number of proxies that append to
`X-Forwarded-For`; the example above replaces the header, so 1; ADR-0011) on the backend, give `/metrics` scrapers
`ZT_METRICS_TOKEN` (no peer address is trusted), serve over HTTPS and keep
`ZT_COOKIE_SECURE=true`. If the UI is ever served from a different origin, add it to `ZT_CORS_ORIGINS`
(the same-origin setup above needs nothing).

## Tests

```bash
npm test           # vitest: 15 API-client tests (refresh single flight, error parsing, step-up retry, Content-Disposition)
```

`e2e/live.mjs` is a Playwright walk-through against a running stack (not part of `npm test`):

```bash
npm i -D playwright   # already in devDependencies
ZT_ADMIN_USER=admin ZT_ADMIN_PASSWORD=... PW_CHROMIUM=/path/to/chrome node e2e/live.mjs
```

The backend runs with its default `require_mfa_for_login=true`. The script registers users (checking the
uniform "if the username is available…" answer), shows the restricted password-only session, enrols TOTP for
every account inside the self-enrolment window (codes computed in the script), signs in again with a code
(activation does not upgrade the session), uploads a 3-chunk file, downloads it and compares SHA-256, checks
the chunk grid, checks that the second user cannot see the file (404), shares, exercises the step-up dialog,
verifies the audit chain, injects and clears a simulated provider fault, and walks the recovery path (admin
resets a user's MFA → the user's enrolment asks for an admin enrolment code → admin issues one → the user
enrols with it). Screenshots go to `docs/screenshots/` (the enrolment code itself is never captured). It needs
a fresh bootstrap admin without MFA. Last run (2026-11-23): `54/54 checks passed`; the containerised alternative is in `deploy/`.

## How authentication works in the client (`src/api/client.ts`)

* **Access token in memory only.** It lives in a closure inside the API client. Nothing auth-related is
  written to `localStorage`/`sessionStorage` (only the theme preference is stored). A page reload therefore
  loses the token; on start-up the app calls `POST /api/auth/refresh` once, which uses the HttpOnly cookie.
* **401 → single-flight refresh → retry once.** Concurrent requests that get 401 share one refresh call.
  If refresh fails, or the retried request is 401 again, the session is treated as ended and the login
  screen is shown ("Your session ended…"). Login/register are sent as anonymous calls and never trigger a
  refresh.
* **403 step-up.** A 403 whose `reasons` include `mfa-required`/`mfa-stale` or whose `obligations` include
  `step-up-mfa` opens the "Confirm with your authenticator" dialog (`src/auth/StepUp.tsx`). After
  `POST /api/auth/mfa/verify` succeeds the original request is retried once; concurrent demands share one
  dialog. If the obligations include `enroll-mfa` the dialog is not opened; the error tells the user to enrol
  MFA under Account.
* **Errors are shown as the server sent them:** status, `error`, each `reason`/`obligation` code (with a
  plain-language hint for known codes), `Retry-After` for 429, and the `request_id` with a copy button, so the
  event can be found in the Audit explorer (Request ID filter).
* **Logout** calls `POST /api/auth/logout` (revokes the session and clears the cookie), then drops the token.
* `/api/auth/me` is re-read every 20 s while the tab is visible, so role changes, MFA freshness and
  restricted-session state show up without a reload. The server re-checks everything on every request; the
  UI hides controls a role cannot use only as a convenience.
* Downloads use `fetch` with the bearer token → `Blob` → object URL. The filename comes from
  `Content-Disposition` (`filename*` preferred). The browser hashes the bytes with WebCrypto and shows them
  next to the server's `X-Content-SHA256`, plus a field to compare against a hash you already trust.
* Uploads use an `XMLHttpRequest` transport (for progress) plugged into the same client pipeline, sending the
  `classification` field before the file part as the API requires (and as a query parameter).
* All server strings are rendered as React text; there is no `dangerouslySetInnerHTML`.

## Screens

| Route | Screen | Data |
|---|---|---|
| (signed out) | Sign in / Create account: password policy hint, uniform "if the username is available your account was created" answer to registration (202), TOTP field after `mfa-required`, generic 401 explanation (lockout/disabled/outside-allow-list look the same by design), 429 handling | `/api/auth/register`, `/api/auth/login` |
| `/` | Dashboard: files, chunks, bytes, ciphertext per provider, operations by outcome, provider health, recent security events; refreshes every 10 s | `/api/dashboard` |
| `/files` | File manager: upload (picker, drag and drop, classification, progress), list, metadata panel, download with SHA-256 comparison, replica verify (scrub), repair, share/unshare, delete (step-up) | `/api/files*` |
| `/distribution` | Storage distribution: provider health cards (latency, consecutive failures, circuit state, injected-fault flag, last error), chunk × provider grid per file with replica and replication status, replicas per provider, storage operation/failure counters; admins: all files' placement and **SIMULATED FAULT** controls when the backend enables fault injection | `/api/storage/*`, `/api/files/{id}/distribution`, `/api/admin/files` |
| `/security` | Security centre: authentication events, access denied, suspicious activity (anomaly detections, lockouts, active blocks with lift for admins), integrity failures, policy settings (admin edit, step-up) and policy rules | `/api/security/*`, `/api/audit/events` |
| `/audit` | Audit explorer: filters (event type incl. `prefix.*`, action, outcome, severity, actor pseudonym, resource id, request id, time range, order), pagination, event drawer (seq, hash, prev_hash, details), hash-link column; auditors/admins: Verify chain report with findings, checkpoint list; admins: create checkpoint. Users are limited to their own events by the server | `/api/audit/*` |
| `/account` | Profile and audit pseudonym, MFA enrol (QR + secret; on `403 mfa-enrollment-requires-approval` a field for the admin enrolment code), activate (then "sign out and sign in again" for an MFA-verified session), verify, disable, active sessions with revoke, change password | `/api/auth/*` |
| `/admin` | Admin: users (role, clearance, disable/enable, CIDR allow list, revoke sessions, issue MFA enrolment code (shown once), reset MFA), KMS key metadata and rotation (the audit-pseudonym key cannot be rotated through the API, finding M3). Auditors see only read-only key metadata: they hold `kms:read` but not `user:list` and work with audit pseudonyms only (finding M1) | `/api/admin/*` |

## Layout

```
src/api/client.ts        HTTP client (token, refresh, step-up, errors, XHR upload transport)
src/api/client.test.ts   vitest unit tests
src/api/types.ts         response shapes from docs/API.md
src/auth/                AuthContext (session state), StepUp (MFA dialog)
src/components/          Layout (sidebar), shared UI (errors, pills, bars, hash chips, modal, drawer), EventTable
src/screens/             one file per screen
src/styles.css           design tokens (light and dark) and styles
e2e/live.mjs             live Playwright walk-through
```

## Known limitations

* Upload progress covers the browser→server transfer; the server's encrypt-and-distribute phase is shown as
  an indeterminate "Encrypting and distributing chunks…" state (the API reports no progress for it).
* The download is buffered in memory in the browser (Blob) to hash it before saving, so very large files
  (the server allows 256 MiB) use that much memory.
* The Security centre's "integrity failures" tab filters `/api/security/events` (newest 500 warning-or-worse
  events) by event type and reason; older integrity events are reachable through the Audit explorer.
* Fault controls need a fresh MFA check just to read the fault status (`GET /api/storage/faults` is gated by
  `storage:admin`), so they load on demand.
* Polling (10–20 s) is used instead of server push; there is no websocket API.
