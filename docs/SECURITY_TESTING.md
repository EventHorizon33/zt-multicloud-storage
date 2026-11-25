# Security testing

This document records the security validation of the backend: the attack
scenarios derived from the UNC5537 case study and the threat model, the
provider-failure scenarios against the real storage emulators, the end-to-end
demonstration, every weakness found by our own testing (Phase 8, F1–F6) and by
an independent security review (H1–I2, section 4a). Everything below was
**run**; the result lines are copied verbatim from the runs.

**History.** In Phase 8 nothing in `backend/app` was changed: each weakness
found was written as a **strict xfail** test that turned the suite red the
moment it was fixed. In the fix phase (2026-11-13) F1–F6 were fixed and every
xfail became a plain passing test. An independent review then reported 17
items (section 4a); all were fixed and each has a `test_fixed_*` regression
test in `backend/tests/review/`. Sections 3, 5 and 6 and
`docs/demo-output.txt` were regenerated on **2026-11-23** from runs made
after all fixes. Section 3 and `docs/demo-output.txt` were regenerated again on **2026-11-25**, after 37 tests
for the deployment settings and the benchmark tooling were added (no application code changed).

## 1. What is where

| Path | Content |
|---|---|
| `backend/tests/security/conftest.py` | Harness: the integration TestClient + real container (LocalKMS, crypto engine, orchestrator, audit, auth, PDP/PEP, detection), injected clock, fault-injecting in-memory providers; `SecEnv` helpers (per-request `X-Request-ID` so each attack is joined to its audit records, raw `sqlite3` access to the audit DB, auditor promotion); the session-wide **secret registry** used by S17; the **evidence recorder** (`ZT_SECURITY_EVIDENCE=<file>`) |
| `backend/tests/security/test_s01_s02_authentication.py` | S01 unauthenticated access, S02 expired token / session |
| `backend/tests/security/test_s03_s04_authorization.py` | S03 horizontal access + ID guessing, S04 admin-only operations, admin separation of duties |
| `backend/tests/security/test_s05_s07_data_integrity.py` | S05 chunk tampering, S06 manifest tampering, S07 reorder/substitute/truncate |
| `backend/tests/security/test_s08_audit_tampering.py` | S08 audit DB tampering, verification endpoint, anchor collision finding |
| `backend/tests/security/test_s09_provider_compromise.py` | S09 compromised provider credential and the stated two-provider limit |
| `backend/tests/security/test_s10_brute_force.py` | S10 lockout, TOTP brute force, credential stuffing, rate limiting |
| `backend/tests/security/test_s11_s15_unc5537.py` | S11–S15 the UNC5537 kill chain (stolen password, allow list, bulk export, refresh-token theft, revocation) |
| `backend/tests/security/test_s16_input_handling.py` | S16 path traversal, header/markup injection, oversize uploads, malformed IDs, injection in filters |
| `backend/tests/security/test_s17_audit_privacy.py` | S17 raw scan of every scenario's audit DB for every secret used |
| `backend/tests/security/test_e01_provider_failures.py` | E01–E07 provider failures against moto / Azurite / gcp-storage-emulator (`@pytest.mark.emulator`) |
| `backend/tests/review/` | 42 `test_fixed_*` regression tests for the independent review (section 4a): `test_review_auth.py`, `test_review_audit.py`, `test_review_input_config.py` |
| `scripts/attacks/run_all.sh`, `scripts/attacks/report.py` | Run the suite and print the scenario → attempt → mechanism → result → audit table (from observed evidence) |
| `scripts/demo.sh`, `scripts/demo/demo.py` | 16-step demonstration against the real server over HTTP and the real emulators (default policy `require_mfa_for_login=true`: every account enrols TOTP with pyotp and signs in again with a code) |
| `docs/demo-output.txt` | Transcript of the last `scripts/demo.sh` run |
| `backend/tests/integration/app/test_large_files_and_chunk_sizes.py` | A single download above the whole detector budget is blocked; a threshold of twice the file size admits two downloads and blocks the third; files written under another chunk size stay readable and verifiable |
| `backend/tests/unit/deploy/test_deployment_config.py` | docker-compose.yml, nginx.conf and `Settings` agree (cap, detector budget, nginx body limit and read timeout, chunk size, deadline); framework defaults unchanged |
| `backend/tests/unit/bench/` | Logic of `scripts/bench/`: volume model, byte budget, bucket-name and credential safety checks, cleanup and failure handling, emulator-start retry, bootstrap statistics, and a scan that no file needs Python 3.12 f-string syntax |
| `scripts/bench/` | Benchmark, per-stage timing, chunk-size sweep, large-file experiments (`limits.py`, section 3a) and a real-cloud benchmark; `scripts/bench/results/` holds the raw data |

All security tests carry `@pytest.mark.security`; the emulator ones also carry
`@pytest.mark.emulator` and skip with a reason when an emulator is unreachable.

## 2. How to run

```bash
scripts/emulators.sh start                                   # moto, Azurite, gcp-storage-emulator
cd backend && .venv/bin/python -m pytest tests/security -q -rs   # 108 tests
scripts/attacks/run_all.sh                                   # same suite + results table (starts/stops emulators it needs)
scripts/attacks/run_all.sh --markdown                        # also prints the table as markdown
scripts/demo.sh                                              # end-to-end demonstration (starts/stops everything it needs)
cd backend && .venv/bin/python -m pytest -q -rs              # whole backend suite (1236 tests)
cd backend && .venv/bin/python -m pytest tests/review -q      # independent-review regression tests (42)
```

`run_all.sh --no-emulators` runs only the in-memory scenarios; E01–E07 then
SKIP with e.g. `moto S3 emulator not reachable at http://127.0.0.1:1 (run
scripts/emulators.sh start)` (verified by pointing `ZT_S3_ENDPOINT_URL` at a
closed port).

Notes for reproducibility:

* The emulator scenarios use a **private bucket per test session**
  (`zt-sec-<random>`) and delete every object in it after each test; the demo
  uses a **private bucket per run** (`zt-demo-<random>`, via `ZT_EMU_BUCKET`)
  and empties it on exit. Since the F4 fix the integration emulator tests
  (`tests/integration/app/test_app_emulators.py`, `tests/integration/storage/`)
  also default to a private per-run bucket (`zt-it-<random>`; `ZT_EMU_BUCKET`
  pins a name). Anchors are now namespaced per audit log, so a shared bucket
  would no longer break audit verification; the private buckets keep fault
  injection and cleanup away from other users of the emulators.
* E01 and E07 kill and restart the GCS emulator with `scripts/emulators.sh
  stop-one/start-one gcs` (always restarted in `finally`). They skip if GCS is
  not managed by that script.

## 3. Results (verbatim)

Final verification run, 2026-11-25, emulators running (`scripts/emulators.sh start`; `scripts/emulators.sh status` showed all three `running` before the suite started).

Whole backend suite (`cd backend && .venv/bin/python -m pytest -q -rs`), exit status 0:

```
1273 passed, 1 warning in 205.80s (0:03:25)
```

(968 unit, 155 integration, 108 security, 42 independent-review tests by
`--collect-only`; 37 of them are new on 2026-11-25.) No test failed, none was skipped (all emulators were
reachable), and there are no xfails. The one warning is a third-party
deprecation warning (`StarletteDeprecationWarning` from `fastapi.testclient`).

Security suite through `scripts/attacks/run_all.sh --markdown` (which runs
`pytest tests/security -q -rs -rx` and prints the scenario table), exit status 0:

```
108 passed, 1 warning in 80.71s (0:01:20)
Totals: PASS=108
```

Demonstration: `scripts/demo.sh` completed all 16 steps, exit 0:

```
    46/46 checks passed
```

Transcript in `docs/demo-output.txt`. Frontend (section 8): `npm run build`
exit 0 (`✓ built in 495ms`), `npx vitest run` → `Tests  15 passed (15)`. The live
Playwright walk-through (`54/54 checks passed`) was last run on 2026-11-23 and was **not re-run** on 2026-11-25
(no browser is installed in the test environment).

Earlier runs: after the F1–F6 fixes the suite was `1192 passed`; the 42
review tests were added later; `1236 passed` on 2026-11-23, before the 37 deployment and tooling tests. History (Phase 8, before the fixes): security suite `98 passed, 8 xfailed, 1
warning in 34.82s`; whole suite `1 failed, 1152 passed, 8 xfailed` on the
shared `zt-chunks` bucket (the failure was F4 observed in the wild: another
deployment's `anchors/audit/checkpoint-000000000195.json` made
`test_full_flow_through_three_real_adapters` report `anchor-mismatch`) and
`1153 passed, 8 xfailed` on an isolated bucket; demo `36/36 checks passed`.

## 3a. Large-file experiments (2026-11-25)

These are experiments, not pytest tests: `scripts/bench/limits.py`, with the raw results in
`scripts/bench/results/phase2-20261125/` (`defaults.json`, `big.json`, `boundary.json`). They ran against local
emulators, with test-only settings where stated. The pytest tests that encode the behaviour are
`backend/tests/integration/app/test_large_files_and_chunk_sizes.py` and `backend/tests/unit/deploy/test_deployment_config.py`.

| Test | Settings | Result |
|---|---|---|
| E1 | shipped cap (256 MiB), 300 MiB upload | `413 request-too-large` in 0.29 s; a 1 MiB upload straight afterwards: 201 |
| E2 | cap raised to 700 MiB, detector at its default (512 MiB) | 600 MiB upload 201; its download `403 access-denied` (`download-rate-exceeded`); a 1 MiB download by the same user afterwards 403; audit: one CRITICAL `security.anomaly.bulk-download`, reason `download-bytes-threshold` |
| E3 | as E2, byte threshold raised | 600 MiB download 200, bytes match |
| Boundary | threshold 20 GiB, file 10 GiB | downloads 200 (92.1 s), 200 (95.0 s), 403; one CRITICAL audit event |
| 2, 5, 10 GiB | cap and detector raised, 16 MiB chunks, 30 s provider deadline | upload 24.4, 66.8, 140.3 s; download 16.5, 46.5, 91.6 s; first byte after 10.5, 27.5, 55.5 s; server peak memory 348, 383, 346 MiB; all bytes match |
| 3 GiB at 8 MiB/s | as above | the upload ran 384.3 s (longer than the 5-minute access token) and returned 201; the old token afterwards: 401; a fresh login downloaded the file, bytes match |

What this shows: a single legitimate download larger than the detector's whole byte budget is treated as bulk
exfiltration (the user is blocked for 10 minutes), so a deployment that serves large files must raise the
threshold, which weakens that control (`deploy/README.md`). Limitations: local emulators only, one transfer at a
time, nothing above 10 GiB, no browser upload, and the Docker stack and nginx were never run.

## 4. Findings

Severity is my assessment for this system's stated threat model (UNC5537:
stolen passwords). The *history* blocks keep the original Phase 8 text; their
file/line references are to the code as it was then.

| # | Finding | Severity | Status |
|---|---|---|---|
| F1 | MFA enrolment hijack from a password-only session | high | **fixed** (ADR-0010) |
| F2 | Network allow list not enforced at login, refresh and account-management endpoints | medium-high | **fixed** |
| F3 | Username enumeration via registration | low | **fixed** |
| F4 | Audit anchors not namespaced per deployment | medium | **fixed** (ADR-0006 amendment) |
| F5 | Storage-layer audit events carry no request context | low-medium | **fixed** |
| F6 | Rate-limit rejections not audited | low | **fixed** |

### F1 — FIXED: MFA enrolment hijack from a password-only session
* **Status:** fixed. Design in ADR-0010 (`docs/adr/README.md`).
* **Fix:**
  * `AuthService.activate_mfa` (`backend/app/auth/service.py`) no longer stamps
    `mfa_verified_at` on the enrolling session and no longer revokes other
    sessions. MFA-verified status comes only from a login with `totp_code` or a
    step-up. Activation is audited `auth.mfa_activate` at WARNING, reason
    `new-factor`, `details.method` = enrolment basis.
  * `AuthService.enroll_mfa` gates the first factor: allowed only for an account
    that never had a factor (`MfaFactorState.ever_enabled`, new table in
    `backend/app/models.py`) within `mfa_self_enroll_window_seconds` (default
    24 h) of registration, or for the bootstrap admin while no other active
    admin holds a factor, or with a single-use admin enrolment code
    (`MfaEnrollmentCode`, only a user-bound HMAC stored, 24 h). Otherwise
    `403 mfa-enrollment-requires-approval` (audited WARNING). Replacing a factor
    needs a code from the current one.
  * New admin endpoints (`backend/app/api/routes_admin.py`,
    `backend/app/admin/service.py`): `POST /api/admin/users/{id}/mfa-enrollment-code`
    and `POST /api/admin/users/{id}/mfa-reset`, both `user:manage` plus admin
    MFA verified within the step-up window (enforced in code), audited.
  * `require_mfa_for_login` now defaults to **true** (`backend/app/config.py`,
    `backend/app/policy/config.py`); restricted sessions can still reach
    `/api/auth/mfa/*`.
  * Frontend: enrolment handles `mfa-enrollment-requires-approval` with an
    admin-code field and tells the user to sign in again after activation; the
    Admin screen issues codes and resets MFA.
* **Tests:**
  `test_s11_s15_unc5537.py::test_s11_mfa_enrolment_from_stolen_password_session_does_not_grant_step_up`,
  `::test_s11_mfa_enrolment_hijack_with_require_mfa_for_login` (both former
  xfail), `::test_s11_mfa_enrolment_hijack_is_blocked_and_audited` (rewritten
  from `test_s11_mfa_hijack_impact_is_at_least_audited`, which asserted the old
  vulnerable behaviour: it now shows that outside the window enrolment is refused
  with 403 and an audit record, that inside the window activation grants no
  step-up, so the confidential download is still denied and the victim keeps
  their sessions, and that the admin reset recovers the account),
  `::test_s11_stated_limit_tofu_window` (residual, below);
  `tests/unit/auth/test_auth_mfa_enrollment.py` (window, codes single-use /
  HMAC-only / expiry / user binding / revocation, rotation, bootstrap, reset);
  `tests/integration/app/test_app_auth.py::test_default_policy_requires_mfa_and_activation_needs_a_new_login`,
  `::test_admin_enrolment_code_flow`, `::test_admin_mfa_reset_revokes_sessions`.
* **Residual risk:** a password stolen *inside* the 24 h TOFU window, before
  the owner enrols, lets the thief enrol their own factor and step up with it
  (detected, recoverable, not prevented). Until the bootstrap admin enrols, its
  password alone can establish the admin factor. Admin enrolment codes are a
  privileged path. The suggested user notification on enrolment from a new
  network was not implemented (there is no notification channel); enrolment
  and activation are audited at WARNING with the source network instead. See
  `docs/THREAT_MODEL.md`.

**Original finding (Phase 8, kept as history):** F1 — VULN (high): MFA enrolment hijack from a password-only session

* **Where:** `backend/app/api/routes_auth.py:160` (`mfa_enroll`) and `:168`
  (`mfa_activate`) need only `get_caller` (any authenticated, even restricted,
  session); `backend/app/auth/service.py:583` `enroll_mfa` and `:606`
  `activate_mfa`, which at `:628` marks the *current* session MFA-verified and
  at `:631` revokes every other session of the user.
* **Exploit:** infostealer password of a user who has not enrolled MFA →
  `POST /api/auth/login` (200, `mfa_verified=false`) → `POST
  /api/auth/mfa/enroll` (attacker receives the seed) → `POST
  /api/auth/mfa/activate` with a code from the attacker's authenticator →
  the attacker's session is now step-up fresh: confidential downloads,
  delete and share succeed. The victim's sessions are revoked and their next
  password login answers `mfa-required` for a factor only the attacker holds,
  so the victim is locked out. Works with `require_mfa_for_login=true` too,
  because restricted sessions may reach enrol/activate by design.
* **Tests:** `test_s11_mfa_enrolment_from_stolen_password_session_does_not_grant_step_up`,
  `test_s11_mfa_enrolment_hijack_with_require_mfa_for_login` (xfail), and
  `test_s11_mfa_hijack_impact_is_at_least_audited` (passes; shows the attacker
  receiving the plaintext of a confidential file).
* **Fix (suggested):** treat first-time factor enrolment as a privileged
  bootstrap. (a) Do not stamp `mfa_verified_at` on the enrolling session and
  do not revoke other sessions on activation. Require a fresh login with the
  new factor, or a cooling-off period, before step-up actions are allowed.
  (b) Better: require an out-of-band enrolment token, or admin approval, for
  accounts that already exist and hold data. Notify the user and audit with
  severity `warning` when a factor is enrolled from a network the user has
  not used before. (c) Apply the CIDR allow list to enrolment (see F2).

### F2 — FIXED: network allow list not enforced at login, refresh and account-management endpoints
* **Status:** fixed.
* **Fix:** `AuthService.network_allowed` (same semantics as the PDP guard, reusing
  `app.policy.pdp.ip_allowed`). `login` checks it right after loading the user
  and before the password: generic 401, audited `auth.login` failure reason
  `network-not-allowed`, no lockout increment (an outsider cannot lock the owner
  out). `refresh` refuses with the generic 401 (audited) without consuming the
  token. `change_password`, `enroll_mfa`, `activate_mfa`, `verify_mfa_step_up` and
  `disable_mfa` call `_require_network` → `403 network-not-allowed`, audited per
  event type.
* **Tests:** `test_s11_s15_unc5537.py::test_s12_login_from_outside_the_allow_list_is_refused`
  (former xfail; now also covers refresh and the absence of lockout),
  `::test_s12_account_takeover_actions_from_outside_the_allow_list_are_refused`
  (former xfail; password change and all four MFA endpoints),
  `::test_s12_valid_credentials_from_outside_the_allow_list_cannot_use_the_api`
  (now logs in from inside and replays the token from outside, since login from
  outside no longer succeeds); `tests/unit/auth/test_auth_mfa_enrollment.py`
  (`test_login_outside_allow_list_is_generic_401_and_not_counted`,
  `test_refresh_outside_allow_list_is_refused_without_consuming`,
  `test_account_management_outside_allow_list_is_403`).

**Original finding (Phase 8, kept as history):** F2 — VULN (medium-high): network allow list not enforced at login, refresh and account-management endpoints

* **Where:** `backend/app/auth/service.py:368` (`login`) and `:444`
  (`refresh`) never consult `users.allowed_cidrs`. The allow list is only a
  PDP guard (`network-not-allowed`), and `/api/auth/*` routes do not call the
  PDP: `backend/app/api/routes_auth.py:76` login, `:93` refresh, `:160`/`:168`
  MFA enrol/activate, `:213` password change.
* **Exploit:** valid credentials from outside the allowed CIDR return 200 with
  an access token, a refresh cookie and a live session. `auth.login` is
  audited as `success`. From there the attacker can change the password
  (`POST /api/auth/password`), which revokes the owner's sessions, or enrol
  MFA (F1). PDP-gated file, audit and dashboard routes do refuse with
  `network-not-allowed` (S12 passes for those).
* **Tests:** `test_s12_login_from_outside_the_allow_list_is_refused`,
  `test_s12_account_takeover_actions_from_outside_the_allow_list_are_refused` (xfail).
* **Fix:** evaluate the allow list in `AuthService.login` and `refresh` after
  the user row is loaded, as a generic 401 with an audited reason
  `network-not-allowed`. Do not count it towards lockout, so it cannot be used
  to lock a victim out. Also require the network check (or a PEP call with an
  `account:manage` action) in password change and MFA enrol, activate and
  disable.

### F3 — FIXED: username enumeration via registration
* **Status:** fixed.
* **Fix:** `POST /api/auth/register` answers `202 {"status": "accepted"}` whether or
  not the name exists (`backend/app/api/routes_auth.py`, `RegisterOut` in
  `schemas.py`). For an existing name no account is created or changed; the
  service spends the same Argon2 hash and audits `auth.register` failure
  `username-taken` internally. Input validation (422) does not depend on
  existence. New setting `allow_self_registration` (default true; false → `403
  registration-disabled`, audited). The frontend says "If the username is
  available your account was created — sign in".
* **Tests:** `test_s10_brute_force.py::test_s10_registration_does_not_reveal_existing_usernames`
  (former xfail), `::test_s10_self_registration_can_be_disabled`;
  `tests/integration/app/test_app_auth.py::test_usernames_are_case_insensitive_and_unique_under_race`
  (now four identical 202s, exactly one account, three `username-taken` audit
  failures).

**Original finding (Phase 8, kept as history):** F3 — VULN (low): username enumeration via registration

* **Where:** `backend/app/auth/service.py:331` (`_create_user` → 409 `username-taken`).
* **Exploit:** `POST /api/auth/register` with each username from a leaked list
  returns 409 for existing accounts and 201 for new ones. That filters a
  credential-stuffing list down to real accounts at 5 probes/min/IP, even
  though login and share deliberately hide whether an account exists.
* **Test:** `test_s10_registration_does_not_reveal_existing_usernames` (xfail).
* **Fix:** if self-registration is required, answer a uniform 202 ("if the
  name is available the account was created") and deliver the outcome out of
  band. Otherwise disable open registration in favour of admin-created
  accounts.

### F4 — FIXED: audit anchors are not namespaced per deployment
* **Status:** fixed. ADR-0006 amendment.
* **Fix:** `backend/app/audit/records.py` `anchor_key(kind, seq, log_id)` →
  `anchors/audit/<log_id>/checkpoint-<seq:012d>.json` (and `retention-`), with
  `AuditService.log_id = sha256(audit-signing public key v1 PEM)[:16]`.
  `verify_chain` lists only `anchors/audit/<log_id>/` and ignores other logs'
  and legacy anchors. The integration emulator tests default to a private
  per-run bucket.
* **Tests:** `test_s08_audit_tampering.py::test_s08_anchors_of_two_deployments_sharing_a_bucket_do_not_collide`
  (former xfail; both deployments verify `ok`, both seq-20 anchors exist side by
  side); `tests/unit/audit/test_audit_anchor_namespace.py` (log id stable
  across rotation, foreign/legacy anchors ignored, truncation still detected
  from the own namespace after a DB wipe).

**Original finding (Phase 8, kept as history):** F4 — BUG/VULN (medium): audit anchors are not namespaced per deployment

* **Where:** `backend/app/audit/records.py:17-23` (`anchor_key` →
  `anchors/audit/checkpoint-{seq:012d}.json`).
* **Effect:** two deployments sharing a bucket (staging and production, a
  reinstall with a new keystore, test runs, the demo) overwrite each other's
  anchors at equal sequence numbers. The overwritten deployment silently loses
  its external tamper evidence for that checkpoint, and its verification
  reports `anchor-mismatch` (so `ok=false`) although nobody tampered. Observed
  three times in this phase: in the demo, in my own test runs, and as the
  `test_full_flow_through_three_real_adapters` failure in section 3.
* **Test:** `test_s08_anchors_of_two_deployments_sharing_a_bucket_do_not_collide` (xfail).
* **Fix:** include a per-log identifier in the key, for example
  `anchors/audit/<sha256(audit-signing public key)[:16]>/checkpoint-…`, and
  make verification ignore anchors outside its own namespace. Separately,
  make the emulator integration tests use a private bucket.

### F5 — FIXED: storage-layer audit events carry no request context
* **Status:** fixed.
* **Fix:** `backend/app/audit/context.py`: a contextvar `AuditContext` opened per
  request by the middleware, actor bound in `get_caller`; `AuditService.record`
  fills missing `request_id`, `source_ip` and actor from it (explicit values
  win). `StorageOrchestrator`'s fan-out pool and `DeadlineRunner`
  (`backend/app/storage/orchestrator.py`, `retry.py`) submit work with
  `contextvars.copy_context().run`.
* **Tests:** `test_s05_s07_data_integrity.py::test_s05_storage_integrity_events_carry_the_request_context`
  (former xfail; `storage.replica.corrupt` and `chunk.retrieve` carry the request
  id, the actor pseudonym and the source /24); `tests/unit/audit/test_audit_context.py`.
* **Note:** a `storage.provider.health` transition observed during a request is
  now attributed to that request's actor (visible in `docs/demo-output.txt`, step
  15); transitions found by the background probe stay unattributed.

**Original finding (Phase 8, kept as history):** F5 — GAP (low-medium): storage-layer audit events carry no request context

* **Where:** `backend/app/storage/orchestrator.py:484-577,664`. `chunk.distribute`,
  `chunk.retrieve`, `storage.replica.corrupt`, `storage.replica.missing` and
  `chunk.repair` are recorded without `request_id`, actor or source network.
  `backend/app/files/service.py:348,546,825` does not pass context into
  `store_chunk`/`fetch_chunk`.
* **Effect:** a critical `storage.replica.corrupt` cannot be joined to the
  download, or the user, that triggered it except by timestamp proximity and
  a chunk-id → file lookup in the metadata DB.
* **Test:** `test_s05_storage_integrity_events_carry_the_request_context` (xfail).
* **Fix:** add an optional `AuditContext`/`RequestContext` parameter to the
  orchestrator data-path methods (or a contextvar) and record
  `request_id`/`actor_id`/`source_ip` on those events.

### F6 — FIXED: rate-limit rejections are not audited
* **Status:** fixed.
* **Fix:** `RateLimitAuditor` (`backend/app/ratelimit.py`, wired in `container.py`,
  called from `api/deps.rate_limit`): the first 429 per (scope, key) per 60 s
  window is audited `security.rate-limited` (denied, WARNING, request id and
  source network; actor for user-keyed scopes); further 429s are counted and
  written as one `kind: "summary"` event when the window is over (bounded state;
  flushed by the maintenance loop and at shutdown).
* **Tests:** `test_s10_brute_force.py::test_s10_rate_limit_rejections_are_audited`
  (former xfail, rewritten for the decided design: the first 429 has a record
  joined to its request, the 4th–6th have none, and after the window one
  summary with `count=3` appears); `tests/unit/test_ratelimit_audit.py`.

**Original finding (Phase 8, kept as history):** F6 — GAP (low): rate-limit rejections are not audited

* **Where:** `backend/app/api/deps.py:91-92` (`rate_limit` raises `RateLimited`; nothing is recorded).
* **Effect:** a sustained login, refresh or download flood above the limit
  leaves no trace in the tamper-evident log. Only the in-memory
  `zt_http_responses_total{status="429"}` counter sees it, and that resets on
  restart.
* **Test:** `test_s10_rate_limit_rejections_are_audited` (xfail).
* **Fix:** audit the first 429 per (scope, key) per window as
  `security.rate_limited` (warning). Aggregate after that so the audit log
  cannot itself be flooded.

### Observations (documented design choices, not marked as failures)
* **Expired access tokens and requests without any token are not audited**
  (`app/auth/service.py` comment "ordinary expiry is not a security event";
  `deps.bearer_token` raises before `authenticate_request`). S01/S02 assert
  this explicitly. Missing-token 401s are visible only in
  `zt_http_responses_total`.
* **No anomaly detection for file-ID enumeration.** 41 guesses produced 41
  audited `authz.decision` denies but no alert, and `GET /api/files/{id}` is
  not rate-limited. With 128-bit random IDs this is informational.
* **Password-only reads of `public`/`internal` files** by a stolen password
  without MFA are allowed only if an operator turns `require_mfa_for_login`
  off (it is on by default since ADR-0010). The S11 test
  `test_s11_stolen_password_without_mfa_cannot_take_sensitive_actions` runs with
  it off (the test harness opts out explicitly) to show the step-up layer on its own.
* **Records after the last checkpoint can be truncated undetected**
  (ADR-0006 stated limit, demonstrated by
  `test_s08_stated_limit_tail_after_last_checkpoint`).
* **Two providers wiped → affected files 503, never wrong bytes**
  (stated limit, demonstrated by `test_s09_stated_limit_two_providers_wiped`).
* **Projection columns** `files.size_bytes`/`chunk_count` and the
  `chunks`/`chunk_replicas` tables are not MAC-protected. They are never used
  for reconstruction (S06 test shows a download stays correct after editing
  them), but they feed the UI and the byte threshold of the bulk-download
  detector.
* **Multipart filenames with raw control characters** cannot be sent by httpx
  (it percent-encodes them), so that sanitiser branch is covered only by the
  unit level (`sanitize_filename`), not end-to-end.

## 4a. Independent security review

After the F1–F6 fixes an independent reviewer audited the code and the
documentation against each other and reported 17 items: 2 high, 5 medium,
8 low, 2 informational, and 2 smaller unconfirmed items. **All are fixed.**
Each fix has at least one regression test named `test_fixed_*` in
`backend/tests/review/` (42 tests, all passing in the run of section 3). The
design changes are recorded in ADR-0007 (amendment), ADR-0010 (amendment) and
the new ADR-0011 (`docs/adr/README.md`), and in `docs/THREAT_MODEL.md` and
`docs/API.md`.

### Three documentation claims that were false, and are now true

| # | Claim (where) | Why it was false | What makes it true now | Finding |
|---|---|---|---|---|
| 1 | "Mapping a pseudonym back to a user requires an explicit, audited admin lookup." (ADR-0007) | `GET /api/admin/users`, open to auditors through `user:list` without MFA, returned `username` + `audit_pseudonym` for every account: a full reverse table, with no `audit.reidentify` record | Auditors lost `user:list`; the user view carries no pseudonym; the only mapping is the admin-only, fresh-MFA, always-audited `POST /api/admin/pseudonym-lookup` | M1 |
| 2 | "A password-only session can only enrol MFA." (THREAT_MODEL, ADR-0010 item 5) | Every `/api/auth/*` endpoint was open to a restricted session, including session list/revoke and password change, so a thief with the password could sign the owner out and change the password | Restricted sessions may use only `me`, `logout`, `refresh`, gated MFA enrol/activate and `security:read`/`policy:read`; session management and password change answer `403 mfa-required` | M5 (with H1) |
| 3 | "No secret has a usable default: the app refuses to start in production mode if required secrets are missing." (`backend/app/config.py`, `.env.example`) | `ZT_ENV` defaulted to `development`, so a deployment that forgot to set it auto-generated a KMS root key next to the keystore, served `/docs` and sent no HSTS | `ZT_ENV` defaults to `production`: no auto-generated root key (startup fails with a clear `KmsError`), no `/docs`/`/openapi.json`, HSTS on; development conveniences need `ZT_ENV=development` explicitly | M4 |

A fourth, smaller documentation error was corrected with H2:
`.env.example` said the backend "uses right-most X-Forwarded-For", which was
true only for the first header line (see H2).

### Findings, fixes and regression tests

| # | Severity | Issue (before) | Fix | Regression test(s) (`backend/tests/review/`) |
|---|---|---|---|---|
| H1 | high | Password change needed only the current password: a stolen session (refresh cookie, MFA stale) plus the password could change it and revoke every other session, evicting the MFA-verified owner | Password change needs a factor verified within the step-up window (`403 mfa-required`/`mfa-stale` + `step-up-mfa`), is refused for accounts without a factor, and never revokes a session that verified the factor more recently than the caller's (ADR-0010 amendment) | `test_review_auth.py::test_fixed_password_change_needs_fresh_mfa_and_cannot_evict_the_mfa_owner`, `::test_fixed_password_change_never_revokes_a_more_recently_verified_session`, `::test_fixed_password_change_refused_for_an_account_without_a_factor` |
| H2 | high | With `ZT_TRUST_FORWARDED_FOR=true` only the **first** `X-Forwarded-For` line was read; behind a proxy that appends its own line the client chose its own IP (allow-list bypass, rate-limit evasion, forged audit network); malformed entries silently fell back | All lines joined (RFC 9110 §5.3); the entry `ZT_TRUSTED_PROXY_HOPS` from the right is the client; any malformed entry or short chain → `400 bad-forwarded-for`; optional `ZT_TRUSTED_PROXY_CIDRS`; resolved IP used everywhere (new ADR-0011) | `test_review_auth.py::test_fixed_xff_joins_all_header_lines_and_takes_the_trusted_hop`, `::test_fixed_malformed_xff_is_rejected_not_ignored` (9 cases), `::test_fixed_xff_port_forms_are_parsed` (3 cases), `::test_fixed_xff_hops_and_trusted_proxy_cidrs`, `::test_fixed_xff_resolved_ip_keys_the_rate_limit` |
| M1 | medium | Auditors could re-identify every pseudonym through the user directory (claim 1 above) | Auditor role without `user:list`; no pseudonyms in the user view; lookup is admin-only, fresh MFA, audited `audit.reidentify` (ADR-0007 amendment) | `test_review_audit.py::test_fixed_auditor_cannot_reidentify_pseudonyms_through_the_user_list` |
| M2 | medium | Unauthenticated audit flooding: every garbage bearer token wrote an `auth.token` record, enough to push critical alerts out of the security feed | Invalid tokens rate limited per client network (`ZT_RATE_LIMIT_INVALID_TOKEN_PER_MINUTE`, default 20; checked **before** any token crypto, 429); failures aggregated (one record per network per window + summary); `/api/security/events` returns a separate `critical` list | `test_review_audit.py::test_fixed_invalid_token_flood_is_rate_limited_aggregated_and_cannot_hide_critical_events`, `::test_fixed_invalid_token_limit_keys_ipv6_by_slash_64`, `::test_fixed_security_feed_keeps_critical_events_under_a_warning_flood` |
| M3 | medium | One admin could rotate the audit-pseudonym key through the API; pseudonyms were computed only with the active version, so all earlier actions became unattributable (an accountability-erasure lever) | API rotation refused (`403 pseudonym-key-rotation-disabled`, audited); rotation is an offline, two-person operation; lookup and every "own events" view match all retained key versions (ADR-0007 amendment) | `test_review_audit.py::test_fixed_pseudonym_key_rotation_is_refused_and_history_survives_offline_rotation` |
| M4 | medium | Insecure default `ZT_ENV=development` (claim 3 above) | Default `production`; unknown values rejected | `test_review_input_config.py::test_fixed_default_env_is_production_and_refuses_to_start_without_a_root_key`, `::test_fixed_production_hides_docs_and_sends_hsts`, `::test_fixed_development_conveniences_need_explicit_env` |
| M5 | medium | Restricted (password-only) sessions could list/revoke sessions and change the password (claim 2 above) | Restricted-session gate on session management and password change (`403 mfa-required` + `enroll-mfa`/`step-up-mfa`) | `test_review_auth.py::test_fixed_restricted_password_only_session_is_limited_to_mfa_enrolment`, `::test_fixed_session_management_needs_an_mfa_verified_session` |
| L1 | low | `/api/auth/me` and session list/revoke ignored the network allow list | Allow list applied (403 `network-not-allowed`, audited) | `test_review_auth.py::test_fixed_session_endpoints_apply_the_network_allow_list` |
| L2 | low | An outsider presenting an already-used refresh token from outside the allow list triggered reuse detection and revoked the victim's live session | Network check runs before reuse detection: generic 401, nothing consumed or revoked, audited WARNING with a reuse-suspected note | `test_review_auth.py::test_fixed_used_refresh_token_from_outside_allow_list_revokes_nothing` |
| L3 | low | Parallel login attempts could exceed `max_failed_logins` (the check and the increment were not atomic) | Each attempt atomically reserves a slot with a conditional `UPDATE` before the slow Argon2 verify; plus a per-user in-process lock | `test_review_auth.py::test_fixed_parallel_login_attempts_cannot_exceed_lockout` (with and without the in-process lock), `::test_fixed_correct_guess_in_a_parallel_batch_only_counts_within_the_limit` |
| L4 | low | IP rate limits keyed on the full IPv6 address: rotating the interface identifier inside one /64 escaped them | Keys are IPv4 address / IPv6 /64 (`ratelimit.client_network_key`) | `test_review_auth.py::test_fixed_login_rate_limit_is_per_ipv6_slash_64`; `test_review_audit.py::test_fixed_invalid_token_limit_keys_ipv6_by_slash_64` |
| L5 | low | `/metrics` trusted loopback peers; behind a same-host proxy every client is `127.0.0.1` | No peer trust: `ZT_METRICS_TOKEN` bearer (≥ 32 chars, constant-time compare) or an admin access token | `test_review_input_config.py::test_fixed_metrics_need_a_token_even_from_loopback` |
| L6 | low | File verify and repair (which re-read every replica of every chunk) were not rate limited: cheap amplification against the providers | Shared per-user budget `ZT_RATE_LIMIT_VERIFY_PER_MINUTE` (default 6) | `test_review_input_config.py::test_fixed_file_verify_and_repair_are_rate_limited` |
| L7 | low | A normal user's own-scope audit export scanned the whole log in Python and was not rate limited | Filtered in SQL (`actor IN (...)`, every pseudonym-key version) and rate limited (`ZT_RATE_LIMIT_AUDIT_EXPORT_PER_MINUTE`, default 6) | `test_review_audit.py::test_fixed_own_scope_audit_export_filters_in_sql_and_is_rate_limited` |
| L8 | low | A client-chosen `X-Request-ID` became the audit `request_id`, so reusing a victim's id mixed two actors under one request in forensics | Request id always server-generated; a valid client id is echoed in `X-Client-Request-ID` and stored as `details.client_request_id` | `test_review_audit.py::test_fixed_request_id_is_server_generated_and_client_id_kept_apart` |
| I1 | info | Malformed multipart bodies raised an unhandled exception (500 with a traceback in the log) | Parse errors → `400 bad-multipart`, exceeded parser limits → `413`; no traceback | `test_review_input_config.py::test_fixed_malformed_multipart_is_a_client_error_without_traceback` |
| I2 | info | Integers beyond SQLite's range in `seq`/`from_seq`/`to_seq`/`offset` caused an `OverflowError` 500 | Bounded to 2^63-1 → 422 | `test_review_input_config.py::test_fixed_out_of_range_integers_are_422` |
| X1 | low (unconfirmed, closed) | Replacing a factor left other sessions marked MFA-verified with the old factor | Replacing a factor clears the MFA-verified status of every other session | `test_review_auth.py::test_fixed_replacing_the_factor_clears_mfa_status_of_other_sessions` |
| X2 | low (unconfirmed, closed) | The case of the configured bootstrap admin username already existing as a non-admin account was not handled explicitly at startup | The server refuses to start with a clear error | `test_review_auth.py::test_fixed_bootstrap_admin_name_held_by_a_non_admin_refuses_to_start` |

Residual effects of the fixes (also in `backend/app/api/NOTES.md`): while a
client network is over the invalid-token limit, valid requests from other
users behind the same NAT or IPv6 /64 also get 429 until the bucket refills;
a wrong `ZT_TRUSTED_PROXY_HOPS` either trusts a client-controlled entry (too
low) or refuses requests (too high, fail closed); the `/metrics` scrape token
is a static bearer secret.

## 5. Attack scenarios (Part 1)

Every row below was produced by the `scripts/attacks/run_all.sh --markdown`
run of section 3 (one row per test; parametrised cases are listed
separately). The *Observed* columns are filled from the actual HTTP response
and the actual audit record the test looked up (by request id, resource id
or event type). There are no XFAIL rows any more.

### S01 — Unauthenticated file access

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Forge a token with alg=none (algorithm confusion) | Algorithm pinned to EdDSA before any signature work | 401 unauthenticated [] | auth.token failure warning reason=token-alg-not-allowed | PASS | `test_s01_s02_authentication.py::test_s01_algorithm_confusion_is_refused[header0-token-alg-not-allowed]` |
| Forge a token with alg=HS256 (algorithm confusion) | Algorithm pinned to EdDSA before any signature work | 401 unauthenticated [] | auth.token failure warning reason=token-alg-not-allowed | PASS | `test_s01_s02_authentication.py::test_s01_algorithm_confusion_is_refused[header1-token-alg-not-allowed]` |
| Present a garbage bearer token | TokenService.verify_access_token (format check) | 401 unauthenticated [] | auth.token failure warning reason=token-malformed | PASS | `test_s01_s02_authentication.py::test_s01_garbage_token_is_401_and_audited` |
| Take a valid token and change sub to another user's id | Ed25519 signature over header+payload | 401 unauthenticated [] | auth.token failure warning reason=token-bad-signature | PASS | `test_s01_s02_authentication.py::test_s01_modified_payload_breaks_signature` |
| Request alice's file with no Authorization header | get_caller: bearer token required on every file route | no token: 401 unauthenticated []; not audited by design; zt_http_responses_total{status=401} incremented | (none) | PASS | `test_s01_s02_authentication.py::test_s01_no_token_is_401_and_counted` |
| Token signed by the same key but audience=some-other-api | iss/aud claim validation (token-wrong-audience) | 401 unauthenticated [] | auth.token failure warning reason=token-wrong-audience | PASS | `test_s01_s02_authentication.py::test_s01_token_for_another_issuer_or_audience_is_refused[token_audience-some-other-api-token-wrong-audience]` |
| Token signed by the same key but issuer=some-other-service | iss/aud claim validation (token-wrong-issuer) | 401 unauthenticated [] | auth.token failure warning reason=token-wrong-issuer | PASS | `test_s01_s02_authentication.py::test_s01_token_for_another_issuer_or_audience_is_refused[token_issuer-some-other-service-token-wrong-issuer]` |
| Replay a validly signed token minted by ANOTHER deployment (different KMS key) | Ed25519 signature verified with this deployment's KMS token-signing key | 401 unauthenticated [] | auth.token failure warning reason=token-bad-signature | PASS | `test_s01_s02_authentication.py::test_s01_token_from_another_deployment_key_is_refused` |

### S02 — Expired token / expired session

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Use a still-valid token whose session has been idle > 30 min | Session idle expiry checked on every request; session revoked | 401 unauthenticated [] | auth.session failure warning reason=session-idle-expired | PASS | `test_s01_s02_authentication.py::test_s02_expired_session_is_refused_and_audited` |
| Replay an access token after its 300 s lifetime | Strict exp check (no leeway); session row re-read | 401 unauthenticated []; expiry is enforced at exactly exp; not audited by design (routine) | (none) | PASS | `test_s01_s02_authentication.py::test_s02_expired_token_is_refused` |
| Use the refresh cookie after the 12 h absolute session lifetime | Absolute session expiry; refresh bounded by session expiry | 401 unauthenticated [] | auth.refresh failure warning reason=refresh-expired | PASS | `test_s01_s02_authentication.py::test_s02_refresh_after_absolute_session_expiry_is_refused` |

### S03 — User accessing another user's file (incl. ID guessing)

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| bob keeps using alice's file after alice revokes the share | Share row re-read on every request | after unshare: 404 not-found [] | authz.decision denied warning reason=not-owner reasons=['not-owner'] | PASS | `test_s03_s04_authorization.py::test_s03_grantee_access_is_scoped_and_revocable` |
| bob enumerates 40 random file ids + alice's real id | Unknown and foreign ids both 404; each guess is an authz.decision deny | 41/41 guesses -> 404; GET /api/files total=0; /api/admin/files scope=own total=0 | authz.decision denied warning reason=not-owner reasons=['not-owner'] | PASS | `test_s03_s04_authorization.py::test_s03_id_guessing_reveals_nothing_and_every_guess_is_audited` |
| bob calls delete on alice's file id | PEP ownership/share check; non-party denies masked as 404 | 404 not-found [] | authz.decision denied warning reason=not-owner reasons=['not-owner'] | PASS | `test_s03_s04_authorization.py::test_s03_other_users_file_is_indistinguishable_from_nonexistent[delete]` |
| bob calls distribution on alice's file id | PEP ownership/share check; non-party denies masked as 404 | 404 not-found [] | authz.decision denied warning reason=not-owner reasons=['not-owner'] | PASS | `test_s03_s04_authorization.py::test_s03_other_users_file_is_indistinguishable_from_nonexistent[distribution]` |
| bob calls download on alice's file id | PEP ownership/share check; non-party denies masked as 404 | 404 not-found [] | authz.decision denied warning reason=not-owner reasons=['not-owner'] | PASS | `test_s03_s04_authorization.py::test_s03_other_users_file_is_indistinguishable_from_nonexistent[download]` |
| bob calls list-shares on alice's file id | PEP ownership/share check; non-party denies masked as 404 | 404 not-found [] | authz.decision denied warning reason=not-owner reasons=['not-owner'] | PASS | `test_s03_s04_authorization.py::test_s03_other_users_file_is_indistinguishable_from_nonexistent[list-shares]` |
| bob calls metadata on alice's file id | PEP ownership/share check; non-party denies masked as 404 | 404 not-found [] | authz.decision denied warning reason=not-owner reasons=['not-owner'] | PASS | `test_s03_s04_authorization.py::test_s03_other_users_file_is_indistinguishable_from_nonexistent[metadata]` |
| bob calls repair on alice's file id | PEP ownership/share check; non-party denies masked as 404 | 404 not-found [] | authz.decision denied warning reason=not-owner reasons=['not-owner'] | PASS | `test_s03_s04_authorization.py::test_s03_other_users_file_is_indistinguishable_from_nonexistent[repair]` |
| bob calls share-to-self on alice's file id | PEP ownership/share check; non-party denies masked as 404 | 404 not-found [] | authz.decision denied warning reason=not-owner reasons=['not-owner'] | PASS | `test_s03_s04_authorization.py::test_s03_other_users_file_is_indistinguishable_from_nonexistent[share-to-self]` |
| bob calls verify on alice's file id | PEP ownership/share check; non-party denies masked as 404 | 404 not-found [] | authz.decision denied warning reason=not-owner reasons=['not-owner'] | PASS | `test_s03_s04_authorization.py::test_s03_other_users_file_is_indistinguishable_from_nonexistent[verify]` |

### S04 — Forbidden administrative operations; admin separation of duties

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Admin (fresh MFA) downloads / deletes / shares a user's file | Separation of duties: admin-no-content-access constraint in the PDP | download: 403 access-denied ['admin-no-content-access'] | authz.decision denied warning reason=admin-no-content-access reasons=['admin-no-content-access'] | PASS | `test_s03_s04_authorization.py::test_s04_admin_cannot_read_user_file_content` |
| A auditor (with FRESH MFA) calls every admin-only operation | PDP RBAC: user:manage/kms:rotate/policy:write/storage:admin/audit:retention are admin-only | each of 9 admin ops: 403 access-denied ['default-deny'] | authz.decision denied warning reason=default-deny reasons=['default-deny'] | PASS | `test_s03_s04_authorization.py::test_s04_admin_operations_forbidden_for_user_and_auditor[auditor]` |
| A user (with FRESH MFA) calls every admin-only operation | PDP RBAC: user:manage/kms:rotate/policy:write/storage:admin/audit:retention are admin-only | each of 9 admin ops: 403 access-denied ['default-deny'] | authz.decision denied warning reason=default-deny reasons=['default-deny'] | PASS | `test_s03_s04_authorization.py::test_s04_admin_operations_forbidden_for_user_and_auditor[user]` |
| A normal user reads everyone's audit events / runs chain verification | audit:read-all and audit:verify are auditor/admin only; read-own is forced to own pseudonym | verify/stats/users/keys: 403 access-denied ['default-deny'] | authz.decision denied warning reason=default-deny reasons=['default-deny'] | PASS | `test_s03_s04_authorization.py::test_s04_user_cannot_read_all_audit_or_verify` |

### S05 — Modified encrypted chunk at a provider

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Flip one bit in BOTH replicas of one chunk | No intact replica -> all-replicas-corrupt; verify-then-release | 409 integrity-failure ['all-replicas-corrupt'] | file.integrity failure critical reason=all-replicas-corrupt reasons=['all-replicas-corrupt'] | PASS | `test_s05_s07_data_integrity.py::test_s05_bit_flip_in_both_replicas_is_409_without_any_bytes` |
| Flip one bit of one chunk replica at one provider | Per-replica SHA-256 vs MAC'd manifest -> failover to the other replica | 200, plaintext identical; replica on memory-a marked corrupt | storage.replica.corrupt failure critical reason=replica failed integrity verification provider=memory-a | PASS | `test_s05_s07_data_integrity.py::test_s05_bit_flip_in_one_replica_is_served_from_the_other` |
| Corrupt one replica, download, and join the storage alert to the request and user | Ambient AuditContext contextvar (F5) set per request, propagated into the orchestrator thread pool with contextvars.copy_context() | storage.replica.corrupt and chunk.retrieve carry request_id, actor pseudonym and source /24 | storage.replica.corrupt failure critical reason=replica failed integrity verification provider=memory-a | PASS | `test_s05_s07_data_integrity.py::test_s05_storage_integrity_events_carry_the_request_context` |

### S06 — Modified manifest / metadata in the metadata DB

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Set files.owner_id to the attacker's user id in the metadata DB | DEK unwrap context binds (file_id, owner_id) -> key-unwrap-failed | 409 integrity-failure ['key-unwrap-failed'] | file.integrity failure critical reason=key-unwrap-failed reasons=['key-unwrap-failed'] | PASS | `test_s05_s07_data_integrity.py::test_s06_changed_owner_in_db_gives_attacker_nothing` |
| Edit the manifest in the metadata DB: change-replica-location | Manifest HMAC (DEK-derived key) verified before any fetch | 409 manifest-integrity-failure ['manifest-mac-invalid'] | file.integrity failure critical reason=manifest-mac-invalid reasons=['manifest-mac-invalid'] | PASS | `test_s05_s07_data_integrity.py::test_s06_modified_manifest_is_rejected_before_any_chunk_is_fetched[change-replica-location]` |
| Edit the manifest in the metadata DB: change-size | Manifest HMAC (DEK-derived key) verified before any fetch | 409 manifest-integrity-failure ['manifest-mac-invalid'] | file.integrity failure critical reason=manifest-mac-invalid reasons=['manifest-mac-invalid'] | PASS | `test_s05_s07_data_integrity.py::test_s06_modified_manifest_is_rejected_before_any_chunk_is_fetched[change-size]` |
| Edit the manifest in the metadata DB: drop-last-chunk | Manifest HMAC (DEK-derived key) verified before any fetch | 409 manifest-integrity-failure ['manifest-mac-invalid'] | file.integrity failure critical reason=manifest-mac-invalid reasons=['manifest-mac-invalid'] | PASS | `test_s05_s07_data_integrity.py::test_s06_modified_manifest_is_rejected_before_any_chunk_is_fetched[drop-last-chunk]` |
| Edit the manifest in the metadata DB: reorder-chunks | Manifest HMAC (DEK-derived key) verified before any fetch | 409 manifest-integrity-failure ['manifest-mac-invalid'] | file.integrity failure critical reason=manifest-mac-invalid reasons=['manifest-mac-invalid'] | PASS | `test_s05_s07_data_integrity.py::test_s06_modified_manifest_is_rejected_before_any_chunk_is_fetched[reorder-chunks]` |
| Edit the chunks/chunk_replicas projection rows (sha256, replica status) | Reconstruction uses only the MAC'd manifest (ADR-0003) | 200, correct plaintext (projection ignored) | file.download success info | PASS | `test_s05_s07_data_integrity.py::test_s06_projection_tables_are_not_trusted` |

### S07 — Reordered, substituted, truncated chunks

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Swap chunks 0/1 AND re-seal a consistent manifest (simulated MAC-key compromise) | AES-GCM AAD = (version, file_id, index, final) -> tag failure | 409 chunk-integrity-failure ['chunk-auth-failed'] | file.integrity failure critical reason=chunk-auth-failed reasons=['chunk-auth-failed'] | PASS | `test_s05_s07_data_integrity.py::test_s07_aad_binding_stops_reordering_even_with_a_forged_manifest` |
| Delete the last chunk object at every provider holding it | Manifest fixes the chunk count; missing chunk -> 503, never a short file | 503 data-unavailable ['data-unavailable'] | file.download error warning reason=data-unavailable | PASS | `test_s05_s07_data_integrity.py::test_s07_deleting_the_last_chunk_everywhere` |
| Replace file A chunk 0 with file B chunk 0 (same owner, same index) | SHA-256 per chunk; AAD binds file_id; different DEK per file | 409 integrity-failure ['all-replicas-corrupt'] | file.integrity failure critical reason=all-replicas-corrupt reasons=['all-replicas-corrupt'] | PASS | `test_s05_s07_data_integrity.py::test_s07_substituting_a_chunk_from_another_file_of_the_same_user` |
| Swap the contents of chunk 0 and chunk 1 objects at every provider | Per-chunk SHA-256 in the manifest (and AAD index binding) | 409 integrity-failure ['all-replicas-corrupt'] | file.integrity failure critical reason=all-replicas-corrupt reasons=['all-replicas-corrupt'] | PASS | `test_s05_s07_data_integrity.py::test_s07_swapping_two_chunk_objects_at_the_providers` |
| Truncate the last chunk object (drop its tail bytes) at both providers | SHA-256 per chunk + final-flag AAD; no partial delivery | 409 integrity-failure ['all-replicas-corrupt'] | file.integrity failure critical reason=all-replicas-corrupt reasons=['all-replicas-corrupt'] | PASS | `test_s05_s07_data_integrity.py::test_s07_truncating_the_last_chunk` |

### S08 — Tampered audit records (direct SQL)

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Two deployments (different keystores) write checkpoints at the same seq into one shared bucket | Anchors namespaced per audit log: anchors/audit/<log_id>/checkpoint-<seq> (F4, ADR-0006 amendment); verification reads only its own namespace | A and B both verify ok=True; seq 20 anchored at anchors/audit/60eef9a744388568/checkpoint-000000000020.json and anchors/audit/27797700a04ae195/checkpoint-000000000020.json; A: 3 anchor copies checked, findings=[] | - | PASS | `test_s08_audit_tampering.py::test_s08_anchors_of_two_deployments_sharing_a_bucket_do_not_collide` |
| (baseline) verify an untampered audit log | hash chain + signed, anchored checkpoints | ok=true events_checked=32 anchors_checked=3 | audit.verify success info finding_types=[] count=0 | PASS | `test_s08_audit_tampering.py::test_s08_baseline_chain_verifies` |
| DELETE the attacker's 'denied' authz record | Sequence gap + broken prev_hash link | ok=false findings=['chain-broken', 'sequence-gap'] | audit.verify failure critical finding_types=['chain-broken', 'sequence-gap'] count=2 | PASS | `test_s08_audit_tampering.py::test_s08_deleted_record` |
| Edit a checkpoint row (head_hash) to match a rewritten log | Ed25519 signature (key in KMS) no longer verifies | ok=false findings=['anchor-mismatch', 'checkpoint-signature-invalid'] | audit.verify failure critical finding_types=['anchor-mismatch', 'checkpoint-signature-invalid'] count=4 | PASS | `test_s08_audit_tampering.py::test_s08_forged_checkpoint_signature` |
| UPDATE the attacker's 'denied' authz record to outcome='success' | Record hash recomputed by the verifier != stored hash | ok=false findings=['record-modified']; retention -> 409 | audit.verify failure critical finding_types=['record-modified'] count=1 | PASS | `test_s08_audit_tampering.py::test_s08_modified_record` |
| UPDATE a record AND recompute its own hash (attacker knows the formula) | Next record's prev_hash no longer links; signed checkpoint head mismatch | ok=false findings=['chain-broken'] | audit.verify failure critical finding_types=['chain-broken'] count=1 | PASS | `test_s08_audit_tampering.py::test_s08_modified_record_with_recomputed_hash` |
| Admin tries to edit/delete audit records through the API | No mutating audit routes exist (only verify/checkpoint/retention) | DELETE /api/audit/events/{seq}: 405 method-not-allowed [] | audit.verify success info finding_types=[] count=0 | PASS | `test_s08_audit_tampering.py::test_s08_no_api_path_edits_audit_records` |
| Swap two records' positions (seq numbers) | Chain link points at a record elsewhere | ok=false findings=['chain-broken', 'record-modified', 'reordered'] | audit.verify failure critical finding_types=['chain-broken', 'record-modified', 'reordered'] count=8 | PASS | `test_s08_audit_tampering.py::test_s08_reordered_records` |
| (stated limit) delete records written AFTER the last checkpoint | none until the next checkpoint (window = audit_checkpoint_every events) | ok=true (undetected) - 3 records after checkpoint seq 30 removed | audit.verify success info finding_types=[] count=0 | PASS | `test_s08_audit_tampering.py::test_s08_stated_limit_tail_after_last_checkpoint` |
| Delete the newest records (incl. ones covered by a signed checkpoint) | Signed checkpoint (DB + provider anchors) references a seq beyond the head | ok=false findings=['truncated'] | audit.verify failure critical finding_types=['truncated'] count=1 | PASS | `test_s08_audit_tampering.py::test_s08_truncated_tail_after_checkpoint` |
| Delete the tail AND every checkpoint row in the audit DB | Checkpoint anchors on the storage providers (outside the audit DB) | ok=false findings=['checkpoint-missing', 'truncated'] | audit.verify failure critical finding_types=['checkpoint-missing', 'truncated'] count=2 | PASS | `test_s08_audit_tampering.py::test_s08_truncated_tail_and_checkpoint_rows_detected_via_anchors` |

### S09 — Compromised storage-provider credential

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| With provider A's credential: delete-everything (chunks AND audit anchors) | R=2 replication + per-replica SHA-256 failover; verify/scrub + audit anchors report it | all 4 files download byte-identical; verify healthy=false (missing); repair ok; audit verify findings=['anchor-missing'] | storage.replica.missing failure warning reason=replica not found at provider provider=memory-a; file.verify failure warning | PASS | `test_s09_provider_compromise.py::test_s09_destroying_one_provider_does_not_prevent_retrieval[delete-everything]` |
| With provider A's credential: overwrite-everything (chunks AND audit anchors) | R=2 replication + per-replica SHA-256 failover; verify/scrub + audit anchors report it | all 4 files download byte-identical; verify healthy=false (corrupt); repair ok; audit verify findings=['anchor-mismatch'] | storage.replica.corrupt failure critical reason=replica failed integrity verification provider=memory-a; file.verify failure critical | PASS | `test_s09_provider_compromise.py::test_s09_destroying_one_provider_does_not_prevent_retrieval[overwrite-everything]` |
| Read EVERYTHING at one provider with its credential (keys, bytes, metadata) | Chunks are AES-256-GCM ciphertext under opaque random ids; no keys or metadata on providers | 11 chunk objects of 16: opaque ids, entropy>7.5 bit/byte, no metadata, no marker/filename/user id/DEK/KEK/root key | (none) | PASS | `test_s09_provider_compromise.py::test_s09_one_provider_holds_only_opaque_ciphertext_and_no_keys` |
| (stated limit) Wipe TWO providers | No reconstruction beyond R: chunk with no replica -> 503 data-unavailable, never wrong bytes | 6 file(s) 503 data-unavailable, 0 file(s) 200 correct; no corrupted output | file.download error warning reason=data-unavailable | PASS | `test_s09_provider_compromise.py::test_s09_stated_limit_two_providers_wiped` |

### S10 — Repeated failed authentication, stuffing, flooding

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Try one leaked password against 6 different usernames from one /24 | AuthFailureDetector: >=5 distinct accounts failing from one network in the window | 6 x 401; one critical anomaly for 203.0.113.0/24; visible in /api/security/events | security.anomaly.auth-failures failure critical reason=many-accounts-failing-from-one-network count=5 distinct_accounts=5 | PASS | `test_s10_brute_force.py::test_s10_credential_stuffing_across_accounts_raises_anomaly` |
| Guess alice's password 5 times, then use the CORRECT password | Account lockout after max_failed_logins (5) for lockout_seconds (900) | correct password while locked: 401 unauthenticated [] | auth.lockout failure warning reason=too-many-failures failed_count=5; auth.login failure warning reason=account-locked | PASS | `test_s10_brute_force.py::test_s10_lockout_after_n_failures_refuses_correct_password` |
| Flood /api/auth/login from one IP (20 requests) | Per-IP token bucket (rate_limit_login_per_minute=10) -> 429 + Retry-After | 11th..20th request: 429 rate-limited ['rate-limited'] | auth.lockout failure warning reason=too-many-failures failed_count=5 | PASS | `test_s10_brute_force.py::test_s10_login_flood_is_rate_limited` |
| Flood /api/auth/login above the limit (2/min) and look for the 429s in the audit log | RateLimitAuditor (F6): first 429 per (scope, key) per window -> security.rate-limited WARNING with request id + source; later ones aggregated into one summary | 3rd request (first 429): 429 rate-limited ['rate-limited']; 4th-6th: 429, no individual record; after the window: one summary count=3 | security.rate-limited denied warning reason=rate-limited count=1; security.rate-limited denied warning reason=rate-limited count=3 | PASS | `test_s10_brute_force.py::test_s10_rate_limit_rejections_are_audited` |
| Probe registration with a known and an unknown username (enumeration, F3) | Uniform 202 {status: accepted} for both; no duplicate created; username-taken audited internally | existing name: 202; new name: 202 | auth.register failure info reason=username-taken | PASS | `test_s10_brute_force.py::test_s10_registration_does_not_reveal_existing_usernames` |
| Register while the deployment disables self-registration | Setting allow_self_registration=false -> 403 registration-disabled, audited | 403 access-denied ['registration-disabled'] | auth.register denied warning reason=registration-disabled | PASS | `test_s10_brute_force.py::test_s10_self_registration_can_be_disabled` |
| Attacker with the password brute-forces the 6-digit TOTP | TOTP failures share the lockout counter | correct password+TOTP while locked: 401 unauthenticated [] | auth.lockout failure warning reason=too-many-failures failed_count=5 | PASS | `test_s10_brute_force.py::test_s10_wrong_totp_codes_count_towards_lockout` |

### S11 — UNC5537: stolen password with / without MFA

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Stolen password (account inside the TOFU window): enrol + activate own TOTP, then download a confidential file | Activation does not stamp the session MFA-verified (ADR-0010, F1) -> PDP mfa-required | confidential download after activation: 403 access-denied ['mfa-required'] | authz.decision denied warning reason=mfa-required reasons=['mfa-required'] | PASS | `test_s11_s15_unc5537.py::test_s11_mfa_enrolment_from_stolen_password_session_does_not_grant_step_up` |
| Attacker with a stolen password self-enrols THEIR OWN TOTP factor on a non-MFA account | ADR-0010: enrolment gated by TOFU window / admin enrolment code; activation never stamps the session MFA-verified nor revokes other sessions | A (account > 24 h old): enrol: 403 access-denied ['mfa-enrollment-requires-approval']; B (inside TOFU window): confidential download after activation: 403 access-denied ['mfa-required']; victim sessions not revoked; admin mfa-reset revokes the attacker's session | auth.mfa_enroll denied warning reason=mfa-enrollment-requires-approval; auth.mfa_activate success warning reason=new-factor; admin.user.mfa_reset success warning | PASS | `test_s11_s15_unc5537.py::test_s11_mfa_enrolment_hijack_is_blocked_and_audited` |
| Same hijack with require_mfa_for_login=true (restricted session reaches enrol/activate) | Activation leaves the session restricted (mfa-enrollment-required) -> confidential download 403 | confidential download after activation: 403 access-denied ['mfa-enrollment-required', 'mfa-required'] | authz.decision denied warning reason=mfa-enrollment-required reasons=['mfa-enrollment-required', 'mfa-required'] | PASS | `test_s11_s15_unc5537.py::test_s11_mfa_enrolment_hijack_with_require_mfa_for_login` |
| (STATED LIMIT) password stolen inside the 24 h TOFU window, before the owner enrols: thief enrols own TOTP, then steps up with it | Not prevented (ADR-0010 residual): detective (WARNING auth.mfa_enroll/activate with the thief's network) + recoverable (admin MFA reset) | step-up with the thief's own factor: 200; confidential download then 200 (documented residual risk) | auth.mfa_activate success warning reason=new-factor | PASS | `test_s11_s15_unc5537.py::test_s11_stated_limit_tofu_window` |
| Infostealer password for an MFA-enrolled user, no TOTP | Login requires TOTP once MFA is enrolled; no session is created | 401 unauthenticated ['mfa-required'] | auth.login failure warning reason=mfa-required | PASS | `test_s11_s15_unc5537.py::test_s11_stolen_password_but_mfa_enrolled_cannot_log_in` |
| Infostealer password for a user WITHOUT MFA: log in, download confidential, delete, share | Step-up MFA required for confidential+ reads, delete, share (mfa-required + obligations) | confidential download: 403 access-denied ['mfa-required'] | authz.decision denied warning reason=mfa-required reasons=['mfa-required'] | PASS | `test_s11_s15_unc5537.py::test_s11_stolen_password_without_mfa_cannot_take_sensitive_actions` |

### S12 — UNC5537: login from outside the network allow list

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Token of a session opened inside the allow list used from outside for password change and MFA enrol/activate/verify/disable | AuthService._require_network (F2): 403 network-not-allowed, audited per endpoint | password change / MFA enrol / activate / verify / disable: 403 access-denied ['network-not-allowed'] | auth.password_change denied warning reason=network-not-allowed | PASS | `test_s11_s15_unc5537.py::test_s12_account_takeover_actions_from_outside_the_allow_list_are_refused` |
| Valid password for alice from outside her allow list (login + refresh) | AuthService.login/refresh check users.allowed_cidrs (F2): generic 401, audited network-not-allowed, no lockout increment | login from outside: 401 unauthenticated []; refresh from outside: 401 unauthenticated [] | auth.login failure warning reason=network-not-allowed; auth.refresh failure warning reason=network-not-allowed | PASS | `test_s11_s15_unc5537.py::test_s12_login_from_outside_the_allow_list_is_refused` |
| Session opened inside alice's allow list (10.20.0.0/16), token replayed from outside | PDP guard network-not-allowed on every PDP-gated request (ADR-0008) | every file/audit/dashboard route: 403 access-denied ['network-not-allowed'] | authz.decision denied warning reason=network-not-allowed reasons=['network-not-allowed'] | PASS | `test_s11_s15_unc5537.py::test_s12_valid_credentials_from_outside_the_allow_list_cannot_use_the_api` |

### S13 — UNC5537: bulk export by a valid session

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Valid session downloads every file in a loop (bulk export) | DownloadDetector count threshold -> DownloadBlock -> PDP download-rate-exceeded | 6th+ download: 403 access-denied ['download-rate-exceeded'] | security.anomaly.bulk-download denied critical reason=download-count-threshold count=6 | PASS | `test_s11_s15_unc5537.py::test_s13_bulk_export_by_a_valid_session_is_blocked_and_alerted` |
| Few but large downloads (byte volume) | DownloadDetector byte threshold | downloads: [200, 200, 403, 403] | security.anomaly.bulk-download denied critical reason=download-bytes-threshold count=3 | PASS | `test_s11_s15_unc5537.py::test_s13_bulk_export_by_volume_is_blocked` |

### S14 — UNC5537: stolen refresh token

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Thief replays a refresh token the legitimate client already rotated | Single-use refresh tokens; reuse -> whole session revoked + critical audit | 401 unauthenticated [] | auth.refresh_reuse failure critical reason=refresh-reuse | PASS | `test_s11_s15_unc5537.py::test_s14_stolen_refresh_token_replayed_after_rotation_revokes_session` |
| Thief uses the stolen refresh token FIRST, gets fresh tokens | Legitimate client's next refresh is a reuse -> session (incl. thief's tokens) revoked | thief's access token -> 401 after the legit client's refresh | auth.refresh_reuse failure critical reason=refresh-reuse | PASS | `test_s11_s15_unc5537.py::test_s14_thief_refreshes_first_then_legit_client_kills_the_session` |

### S15 — Revocation / disablement takes effect immediately

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Admin disables alice / demotes an auditor while their tokens are still unexpired | User row (is_active, role) re-read on every request; disable revokes sessions | disabled user's token: 401 unauthenticated [] | auth.session failure warning reason=session-revoked | PASS | `test_s11_s15_unc5537.py::test_s15_disabled_account_and_demotion_take_effect_immediately` |
| Keep using an access token after its session was revoked (user revokes / logs out) | Session row re-read on every request (ADR-0008) | 401 unauthenticated [] | auth.session failure warning reason=session-revoked | PASS | `test_s11_s15_unc5537.py::test_s15_revoked_session_fails_on_the_next_request` |

### S16 — Hostile input (traversal, oversize, malformed ids, injection)

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Filename with quotes/CRLF/;/<script> to break Content-Disposition or inject HTML | RFC 6266 ASCII fallback + percent-encoded filename*; downloads always octet-stream attachment | Content-Disposition: attachment; filename="script_.html"; filename*=UTF-8''script%3E.html | (none) | PASS | `test_s16_input_handling.py::test_s16_header_and_markup_injection_in_filename` |
| Injection strings as username at login/register/share target | Username pattern ^[A-Za-z0-9_.-]{3,64}$; generic 401; one share-target-invalid code | share to injected username: 422 validation-failed ['share-target-invalid'] | file.share failure warning reason=share-target-invalid | PASS | `test_s16_input_handling.py::test_s16_injection_in_login_register_share` |
| SQL/LIKE/template injection strings in every audit search filter | SQLAlchemy bound parameters; LIKE autoescape; strict query validation | 12 payloads x 6 filters -> 200 total=0 or 422; never 500; chain verifies | audit.verify success info finding_types=[] count=0 | PASS | `test_s16_input_handling.py::test_s16_injection_strings_in_audit_search_filters` |
| Malformed / injection file ids on every file route | FILE_ID_RE (^[0-9a-f]{32}$) before any query; parametrised SQL; 404 for all | 404 not-found [] | authz.decision denied warning reason=not-found reasons=['not-found'] | PASS | `test_s16_input_handling.py::test_s16_malformed_file_ids[id0]` |
| Malformed / injection file ids on every file route | FILE_ID_RE (^[0-9a-f]{32}$) before any query; parametrised SQL; 404 for all | 404 not-found [] | authz.decision denied warning reason=not-found reasons=['not-found'] | PASS | `test_s16_input_handling.py::test_s16_malformed_file_ids[id10]` |
| Malformed / injection file ids on every file route | FILE_ID_RE (^[0-9a-f]{32}$) before any query; parametrised SQL; 404 for all | 404 not-found [] | authz.decision denied warning reason=not-found reasons=['not-found'] | PASS | `test_s16_input_handling.py::test_s16_malformed_file_ids[id11]` |
| Malformed / injection file ids on every file route | FILE_ID_RE (^[0-9a-f]{32}$) before any query; parametrised SQL; 404 for all | 404 not-found [] | authz.decision denied warning reason=not-found reasons=['not-found'] | PASS | `test_s16_input_handling.py::test_s16_malformed_file_ids[id1]` |
| Malformed / injection file ids on every file route | FILE_ID_RE (^[0-9a-f]{32}$) before any query; parametrised SQL; 404 for all | 404 not-found [] | (none) | PASS | `test_s16_input_handling.py::test_s16_malformed_file_ids[id2]` |
| Malformed / injection file ids on every file route | FILE_ID_RE (^[0-9a-f]{32}$) before any query; parametrised SQL; 404 for all | 404 not-found [] | authz.decision denied warning reason=not-found reasons=['not-found'] | PASS | `test_s16_input_handling.py::test_s16_malformed_file_ids[id3]` |
| Malformed / injection file ids on every file route | FILE_ID_RE (^[0-9a-f]{32}$) before any query; parametrised SQL; 404 for all | 404 not-found [] | authz.decision denied warning reason=not-found reasons=['not-found'] | PASS | `test_s16_input_handling.py::test_s16_malformed_file_ids[id4]` |
| Malformed / injection file ids on every file route | FILE_ID_RE (^[0-9a-f]{32}$) before any query; parametrised SQL; 404 for all | 404 not-found [] | authz.decision denied warning reason=not-found reasons=['not-found'] | PASS | `test_s16_input_handling.py::test_s16_malformed_file_ids[id5]` |
| Malformed / injection file ids on every file route | FILE_ID_RE (^[0-9a-f]{32}$) before any query; parametrised SQL; 404 for all | 404 not-found [] | authz.decision denied warning reason=not-found reasons=['not-found'] | PASS | `test_s16_input_handling.py::test_s16_malformed_file_ids[id6]` |
| Malformed / injection file ids on every file route | FILE_ID_RE (^[0-9a-f]{32}$) before any query; parametrised SQL; 404 for all | 404 not-found [] | (none) | PASS | `test_s16_input_handling.py::test_s16_malformed_file_ids[id7]` |
| Malformed / injection file ids on every file route | FILE_ID_RE (^[0-9a-f]{32}$) before any query; parametrised SQL; 404 for all | 404 not-found [] | authz.decision denied warning reason=not-found reasons=['not-found'] | PASS | `test_s16_input_handling.py::test_s16_malformed_file_ids[id8]` |
| Malformed / injection file ids on every file route | FILE_ID_RE (^[0-9a-f]{32}$) before any query; parametrised SQL; 404 for all | 404 not-found [] | authz.decision denied warning reason=not-found reasons=['not-found'] | PASS | `test_s16_input_handling.py::test_s16_malformed_file_ids[id9]` |
| Upload larger than ZT_MAX_UPLOAD_BYTES (declared, and streamed past the cap) | Middleware body cap (413 before any work) + engine max_bytes (413, file FAILED, chunks deleted) | streamed past cap: 413 request-too-large ['upload-too-large'] | file.upload failure warning reason=upload-too-large | PASS | `test_s16_input_handling.py::test_s16_oversize_upload_rejected_and_cleaned_up` |
| Upload with filename '....//....//x.txt' | sanitize_filename: last component, control/format chars removed; never a path or object key | 201, stored display name 'x.txt'; Content-Disposition: attachment; filename="x.txt"; filename*=UTF-8''x.txt | file.upload success info | PASS | `test_s16_input_handling.py::test_s16_path_traversal_filenames_are_display_names_only[....//....//x.txt-x.txt]` |
| Upload with filename '../../etc/passwd' | sanitize_filename: last component, control/format chars removed; never a path or object key | 201, stored display name 'passwd'; Content-Disposition: attachment; filename="passwd"; filename*=UTF-8''passwd | file.upload success info | PASS | `test_s16_input_handling.py::test_s16_path_traversal_filenames_are_display_names_only[../../etc/passwd-passwd]` |
| Upload with filename '..\\..\\windows\\system32\\config\\SAM' | sanitize_filename: last component, control/format chars removed; never a path or object key | 201, stored display name 'SAM'; Content-Disposition: attachment; filename="SAM"; filename*=UTF-8''SAM | file.upload success info | PASS | `test_s16_input_handling.py::test_s16_path_traversal_filenames_are_display_names_only[..\\..\\windows\\system32\\config\\SAM-SAM]` |
| Upload with filename '/var/lib/zt/../../root/.ssh/authorized_keys' | sanitize_filename: last component, control/format chars removed; never a path or object key | 201, stored display name 'authorized_keys'; Content-Disposition: attachment; filename="authorized_keys"; filename*=UTF-8''authorized_keys | file.upload success info | PASS | `test_s16_input_handling.py::test_s16_path_traversal_filenames_are_display_names_only[/var/lib/zt/../../root/.ssh/authorized_keys-authorized_keys]` |
| Upload with filename 'normal\u202etxt.exe' | sanitize_filename: last component, control/format chars removed; never a path or object key | 201, stored display name 'normaltxt.exe'; Content-Disposition: attachment; filename="normaltxt.exe"; filename*=UTF-8''normaltxt.exe | file.upload success info | PASS | `test_s16_input_handling.py::test_s16_path_traversal_filenames_are_display_names_only[normal\u202etxt.exe-normaltxt.exe]` |
| Hostile X-Request-ID (CRLF, JSON, 500 chars) | Request id always server-generated (L8); a client X-Request-ID is kept only if [A-Za-z0-9._-]{1,64}, as client_request_id, otherwise dropped | hostile ids dropped; server-generated id in response, logs and audit; no client_request_id kept | authz.decision denied warning reason=not-found reasons=['not-found'] | PASS | `test_s16_input_handling.py::test_s16_request_id_header_cannot_inject_into_logs` |
| Upload with filename '..', '/', control-only or 300 chars | sanitize_filename -> 422 invalid-filename | 422 validation-failed ['invalid-filename']; rejected before the PEP: no file row, no audit record | (none) | PASS | `test_s16_input_handling.py::test_s16_unusable_filenames_rejected` |

### S17 — Audit privacy scan over every scenario's audit DB

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Check every stored event: actor format, no _dropped detail keys | Pseudonym = 'u_' + HMAC(user id)[:32]; allow-list covers every emitter | every actor matches u_<32 hex>; no _dropped markers | (none) | PASS | `test_s17_audit_privacy.py::test_s17_no_detail_key_was_dropped_and_actor_is_pseudonymous` |
| Steal the audit DB files after all scenarios; grep for every secret used | Privacy filter: allow-listed detail keys, deny-name/value scan, pseudonymous actors, /24 IPs | 109 audit DBs, 2810 events, 634 long secrets + 68 TOTP codes + 6 full IPs: 0 hits | (none) | PASS | `test_s17_audit_privacy.py::test_s17_no_secret_in_any_audit_database` |

## 6. Provider failure scenarios against the real emulators (Part 2)

moto server (S3 API), Azurite (Azure Blob), gcp-storage-emulator (GCS),
accessed through the application's real boto3 / azure-storage-blob /
google-cloud-storage adapters, each wrapped in `FaultInjectingProvider` (pass-
through unless a fault mode is set). Outages are produced by killing the
emulator process. These results show behaviour against emulators, not against
AWS, Azure or GCP.

### E01 — Provider unavailable (emulator process killed)

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Kill the gcp-storage-emulator process (real outage) | Replica failover on read, placement failover on write, health monitor + breaker | health gcs healthy=false injected=false; download 200 byte-identical; new upload replicas on ['aws-s3', 'azure-blob'] | storage.provider.health error warning reason=ProviderUnavailable: gcs health failed: connection failed (ConnectionError) provider=gcs | PASS | `test_e01_provider_failures.py::test_e01_provider_unavailable_reads_fail_over_writes_go_elsewhere` |

### E02 — Chunk not retrievable at one provider

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Delete every Azure copy of a file's chunks via the Azure SDK | ObjectNotFound -> next replica; replica marked missing | 200 (16432 bytes) | storage.replica.missing failure warning reason=replica not found at provider provider=azure-blob | PASS | `test_e01_provider_failures.py::test_e02_object_missing_at_one_provider_served_from_replica` |

### E03 — Corrupted content at a provider

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Overwrite every S3 copy of a file's chunks via boto3 with same-size garbage | SHA-256 mismatch -> corrupt replica skipped; critical audit | 200 (16432 bytes) | storage.replica.corrupt failure critical reason=replica failed integrity verification provider=aws-s3 | PASS | `test_e01_provider_failures.py::test_e03_corrupted_object_detected_and_replica_used` |

### E04 — Timeout (fault injection over the real SDK adapter)

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Every call to Azure times out (fault mode 'timeout' over the real SDK adapter) | Bounded retries with backoff, then replica failover; injected flag kept | 200 byte-identical; azure-blob get retries +3 | chunk.retrieve success warning | PASS | `test_e01_provider_failures.py::test_e04_timeout_is_retried_then_fails_over` |

### E05 — Transient failures, retry succeeds

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| GCS fails the next 2 calls (fault mode fail-n) during upload | RetryPolicy (max 4 attempts) succeeds on the same provider; no failover needed | upload 201; gcs put retries +2; replicas still on gcs | chunk.distribute success info | PASS | `test_e01_provider_failures.py::test_e05_transient_failures_retry_succeeds` |

### E06 — Chunk permanently unavailable

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| Delete one chunk at EVERY provider holding it (via each SDK) | No reconstruction beyond R; 503 data-unavailable, no partial content | 503 data-unavailable ['data-unavailable'] | file.download error warning reason=data-unavailable | PASS | `test_e01_provider_failures.py::test_e06_chunk_permanently_unavailable_is_503` |

### E07 — Repair after a provider returns

| Attempt | Mechanism | Observed behaviour | Audit record (observed) | Outcome | Test |
|---|---|---|---|---|---|
| GCS down AND the other replica of some chunks lost; GCS comes back | Outage -> 503 + unrepairable; provider returns -> repair copies from it, verify healthy | during outage: 503, repair ok=false; after return: repaired 4 chunk(s), verify healthy, 200 | file.repair success info | PASS | `test_e01_provider_failures.py::test_e07_repair_restores_replication_after_provider_returns` |

## 7. The demonstration (Part 3)

`scripts/demo.sh` runs these steps against the real backend
(`scripts/run-dev.sh`, uvicorn on `127.0.0.1:8765`, temporary data dir,
bootstrap admin with a generated password) and the real emulators.

1. Environment up: emulators and server health.
2. Bootstrap admin: the password-only session is restricted
   (`GET /api/admin/users` → 403 `mfa-enrollment-required`, the default
   `require_mfa_for_login=true`); TOTP enrolment + activation (which does
   **not** upgrade that session, ADR-0010); a new login with password + TOTP
   gives an MFA-verified session.
3. Register alice and bob: `202 {"status": "accepted"}`; registering the
   existing name alice again gives the identical answer (F3). The admin
   promotes bob to auditor, giving two roles plus admin.
4. Both log in with the password (restricted), enrol TOTP inside the 24 h
   self-enrolment window, then log in again with password + code
   (`mfa_verified=True`). Role, session and pseudonym are shown; tokens, TOTP
   seeds and codes are never shown.
5. alice uploads a 3.5 MiB file (4 chunks of 1 MiB).
6. Chunk table: opaque IDs, sizes and replica providers (R=2 of 3).
7. Per-chunk ciphertext SHA-256 from the distribution endpoint, and the
   28-byte AEAD overhead per chunk.
8. Raw objects read directly with boto3, azure-storage-blob and
   google-cloud-storage: SHA-256 matches the manifest, entropy about
   8 bits/byte, no plaintext marker, filename or username, and no object
   metadata.
9. Owner download; SHA-256 matches the original, and the `X-Content-SHA256`
   header too.
10. bob (auditor) gets 404 on download, metadata and delete. An anonymous
    client gets 401. Even the admin gets 403 `admin-no-content-access`. All
    of these are audited.
11. One byte flipped in one replica through the S3 SDK. Verify reports it
    corrupt, the download is still byte-identical, the audit log has a
    critical `storage.replica.corrupt`, and repair makes the file healthy.
12. Direct `UPDATE` of bob's denied record in `audit.db`. `POST
    /api/audit/verify` reports `record-modified` at that seq, and the
    verification run is audited as critical.
13. `emulators.sh stop-one gcs`. The download still works, provider health
    shows GCS down (`injected=false`), and a new upload lands on S3 and
    Azure only.
14. GCS restarted. Health recovers and the file verifies healthy.
15. The matching audit events (seq, time, event, outcome, severity,
    pseudonymous actor, role, reason, /24 network), including
    `auth.mfa_enroll` / `auth.mfa_activate` (WARNING, reason `new-factor`).
    The audit DB bytes are then checked to contain none of the passwords,
    tokens, TOTP seeds, the filename or the file content.
16. Summary of the checks.

On exit (trap) the script stops the server, makes sure GCS is running again,
empties and abandons the per-run buckets, restores
`scripts/.emulators/run/emulators.env` to the default bucket, stops only the
emulators it started, and deletes the temporary data dir. While a demo is
running, `emulators.env` points at the demo bucket. A developer who sources it
during that window gets the demo bucket.

## 8. Limitations of this testing

* Everything runs on one host against emulators and an in-process
  TestClient. No real AWS, Azure or GCP, no TLS, no reverse proxy, no
  multi-instance deployment. The PostgreSQL audit-lock path is not exercised.
* Timing side channels (login timing, registration timing for existing vs.
  new names, 404 vs 403 timing) were not measured. Registration does the same
  Argon2 work on both paths, but DB work differs.
* No fuzzing beyond the hand-picked payload list in S16. Dependencies were
  not scanned for CVEs (`pip-audit` was not run).
* The frontend was not tested in Phase 8. In the fix phase it was built
  (`npm run build`), unit-tested (`npx vitest run`, 15 tests: API client only)
  and walked through end-to-end with `frontend/e2e/live.mjs` (Playwright,
  headless Chromium) against a live backend with the default
  `require_mfa_for_login=true`: 54/54 checks on 2026-11-23, including the
  admin enrolment-code recovery path, the auditor key-only view and the
  password-change step-up. There are no React component unit tests.
* The TOFU-window residual of ADR-0010 is demonstrated
  (`test_s11_stated_limit_tofu_window`), not mitigated. The 24 h window and
  the enrolment-code expiry are tested with an injected clock, not in real
  time.
* S17 scans long secrets as raw bytes (main DB, WAL and SHM). Six-digit TOTP
  codes are scanned only in the decoded `reason`, `details`, `resource_id`
  and `request_id` columns, because raw-byte matching of six digits produces
  false positives against timestamps and hashes.
* The demo's step 13 relies on passive health detection (the download
  attempt) plus the 2-second background probe. On a slow host the polling
  loop waits up to 20 s.
