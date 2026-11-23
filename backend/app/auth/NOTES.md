# app/auth — authentication, MFA, tokens, sessions (Phase 2)

Library code only (no routers). All collaborators are injected. Every public
method takes the SQLAlchemy `Session` (`db`) as its first argument and commits
its own changes. Failure state (failed-login counters, lockouts, revocations)
is committed *before* the exception is raised so a caller's rollback cannot
undo it. Success-path audit events are written before commit: if
`audit.record` raises, the operation is rolled back (fail closed).

## Public API

```python
from app.auth import AuthService, LoginResult, AuthenticatedPrincipal, MfaEnrollment, PasswordHasher

AuthService(*, settings: Settings, kms: KeyManagementService, audit: AuditSink,
            clock: Callable[[], datetime],              # aware UTC datetime
            password_hasher: PasswordHasher | None = None,
            last_seen_granularity_seconds: float = 0.0)  # 0 = write last_seen_at every request
  .tokens -> TokenService

  .register(db, username: str, password: str, *, source_ip=None, request_id=None) -> User   # role always "user"
        # existing name -> Conflict(username-taken) after the same Argon2 work; the API maps it to the
        # same 202 as a success (F3). allow_self_registration=false -> AccessDenied(registration-disabled)
  .ensure_bootstrap_admin(db, username: str, password: str) -> User      # no-op if it exists as an admin;
        # Conflict(bootstrap-username-not-admin) if the name belongs to a non-admin (Container.start refuses to start)
  .login(db, username, password, totp_code: str | None = None, source_ip: str | None = None,
         *, request_id=None) -> LoginResult
  .refresh(db, refresh_token: str, source_ip: str | None = None, *, request_id=None) -> LoginResult
  .logout(db, session_id: str, *, source_ip=None, request_id=None) -> bool
  .authenticate_request(db, access_token: str, source_ip: str | None = None, *, request_id=None)
        -> AuthenticatedPrincipal
  .build_subject(user: User, session: Session, now: datetime | None = None) -> contracts.Subject

  .enroll_mfa(db, user, *, enrollment_code=None, current_code=None, session=None, source_ip=None,
              request_id=None) -> MfaEnrollment            # .secret, .otpauth_uri (show once); gated, ADR-0010
  .activate_mfa(db, user, code: str, *, session: Session | None = None, source_ip=None, request_id=None) -> None
        # does NOT stamp the session MFA-verified and revokes no session (F1)
  .issue_mfa_enrollment_code(db, user, *, issued_by: str) -> (code, expires_at)   # no commit/audit: AdminService
  .reset_mfa(db, user) -> bool                                   # no commit/audit/revocation: AdminService
  .network_allowed(user, source_ip) -> bool                      # users.allowed_cidrs, PDP semantics
  .verify_mfa_step_up(db, session: Session, code: str, *, source_ip=None, request_id=None) -> Session
  .disable_mfa(db, user, code: str, *, session: Session | None = None, source_ip=None, request_id=None) -> None

  .change_password(db, user, current_password: str, new_password: str, *, keep_session_id: str | None = None,
                   session: Session | None = None, mfa_max_age_seconds: int | None = None,
                   require_mfa_for_login: bool = True, source_ip=None, request_id=None) -> int
        # H1: the caller's session (``session`` or ``keep_session_id``; none -> refused) must have verified the
        # factor within mfa_max_age_seconds (403 mfa-required/mfa-stale + step-up-mfa); no factor -> 403
        # mfa-required + enroll-mfa. Revokes other sessions EXCEPT those MFA-verified more recently than the
        # caller (details sessions_revoked / sessions_kept). Returns the number revoked.
  .require_network(user, event, *, session_id=None, source_ip=None, request_id=None) -> None      # L1, 403
  .require_mfa_session(user, session, event, *, require_mfa_for_login, fresh_within_seconds=None, ...) -> None
        # M5: restricted (no factor, or not MFA-verified while require_mfa_for_login) -> 403 mfa-required
  .token_failure_gate: Callable[[source_ip], bool] | None   # M2: set to TokenFailureAuditor.admit by the container
  .list_sessions(db, user) -> list[models.Session]                    # live only, newest first
  .revoke_session(db, session_id: str, reason: str, *, owner_id: str | None = None, actor_id=None,
                  source_ip=None, request_id=None) -> bool             # owner_id => must belong to that user
  .revoke_all_sessions(db, user_id: str, reason: str, *, except_session_id=None, actor_id=None,
                       source_ip=None, request_id=None) -> int

@dataclass(frozen=True) LoginResult(access_token: str, expires_in: int, refresh_token: str,
                                    session: models.Session, user: models.User, mfa_verified: bool)
@dataclass(frozen=True) AuthenticatedPrincipal(user: User, session: Session, subject: Subject, claims: AccessClaims)

TokenService(kms, settings, clock)
  .issue_access_token(*, user_id, session_id) -> tuple[str, AccessClaims]
  .verify_access_token(token: str) -> AccessClaims                     # raises AuthenticationError
  .new_refresh_token() -> tuple[str, str]                              # (token, hex HMAC)
  .hash_refresh_token(token) -> str ; .hash_ip(ip) -> str | None

PasswordHasher(*, time_cost=3, memory_cost_kib=65536, parallelism=4)
  .hash(pw) -> str ; .verify(hash, pw) -> bool ; .verify_dummy(pw) -> False ; .needs_rehash(hash) -> bool
validate_password(password, *, username, min_length) -> None           # raises ValidationFailed(reasons=...)
```

### Errors (from `app.errors`)
* `AuthenticationError` (401). `.reasons`:
  * `login`: **empty** for unknown user / wrong password / locked / disabled (indistinguishable).
    After a *correct* password only: `("mfa-required",)` (no code supplied) or `("mfa-invalid",)`.
  * `authenticate_request`: `token-malformed | token-alg-not-allowed | token-bad-signature | token-expired |
    token-not-yet-valid | token-wrong-issuer | token-wrong-audience | token-wrong-type | token-bad-claims |
    session-not-found | session-revoked | session-expired | session-idle-expired | user-disabled |
    ip-mismatch | user-state-invalid`. The API should return a generic 401 and not echo these.
  * `refresh`: `refresh-invalid | refresh-expired | refresh-reuse | session-*  | user-disabled | ip-mismatch`.
  * `login`/`refresh` from outside `users.allowed_cidrs`: generic error (login: no reasons), audited
    `network-not-allowed`, no lockout increment; checked before the password (F2).
* `ValidationFailed` (422): `invalid-username`, `password-too-short|too-long|contains-username|too-common`,
  `password-unchanged`.
* `Conflict` (409): `username-taken` (register; the API hides it), `mfa-already-enabled`, `mfa-not-enrolled`,
  `mfa-enrollment-expired`.
* `AccessDenied` (403): `network-not-allowed` (password change, MFA enrol/activate/verify/disable; F2; and via
  `require_network` for `/me` and session list/revoke, L1), `mfa-required` / `mfa-stale` with `.obligations`
  (`require_mfa_session`, password change; M5/H1), `mfa-enrollment-requires-approval`,
  `mfa-enrollment-code-invalid` (ADR-0010), `registration-disabled`.
* `Conflict` (409): `bootstrap-username-not-admin` from `ensure_bootstrap_admin`.

### Integration notes
* `authenticate_request` returns `principal.subject` ready for the PEP; build `RequestContext` with the
  same `source_ip`. The API should get the user via the principal (DB-fresh), never from token claims.
* `require_mfa_for_login` (default **true**, ADR-0010): login itself is not blocked; the session gets
  `Subject.mfa_verified=False` and the PDP restricts it (see app/policy/NOTES.md). The enrol/activate MFA
  endpoints must be reachable with an authenticated-but-restricted session (they are auth endpoints, not
  PDP-gated actions); they gate themselves (below).
* **MFA enrolment gating (ADR-0010, finding F1).** A first factor may be enrolled without an admin code
  only on one of two bases: `tofu` (the account never had a factor — `MfaFactorState.ever_enabled` — and
  is within `mfa_self_enroll_window_seconds` of `users.created_at`) or `bootstrap` (the configured
  bootstrap admin, never had a factor, and no OTHER active admin holds a factor). Otherwise an admin-issued
  single-use code (`MfaEnrollmentCode`: only `HMAC(lookup-hmac, "mfa-enrollment-code:"+user_id+":"+code)` is
  stored; 80 bits; `mfa_enrollment_code_ttl_seconds`; a new code revokes the previous unused one; consumed
  atomically at enrol). Replacing an existing factor (`rotation`) needs `current_code` (failures count
  towards lockout); the old factor works until the new one is activated. Disable and admin reset set
  `ever_enabled`, so the window never reopens. Enrol → activate within
  `mfa_pending_enrollment_ttl_seconds`. Activation is audited at WARNING (reason `new-factor`,
  `details.method` = basis) and never stamps `mfa_verified_at` nor revokes sessions: MFA-verified status
  comes only from a login with `totp_code` or a step-up.
* Refresh token: deliver in an HttpOnly, SameSite=Strict, Secure cookie scoped to `/api/auth` (ADR-0009).
  `refresh` checks the allow list FIRST (review L2): from outside it, even an already-used token is refused
  without revoking anything (audited `auth.refresh` failure `network-not-allowed`, `details.reuse_suspected`).
* Lockout under concurrency (review L3): `login` reserves an attempt with a conditional
  `UPDATE users SET failed_login_count = failed_login_count + 1 WHERE count < max AND not locked` (committed
  before the Argon2 verify; rowcount 0 -> refused like a locked account). Success resets the counter, a failed
  attempt keeps its reservation (and locks at the limit), a correct password without the TOTP code gives the
  reservation back. A striped per-user in-process lock (256 stripes) serialises attempts per user as a belt.
* Invalid-token audit aggregation (review M2): with `token_failure_gate` set, only the first `auth.token`
  failure per client network per 60 s window is recorded individually (`details.kind = "first"`); the rest
  become one summary (`app.ratelimit.TokenFailureAuditor`). The API rate-limits invalid tokens per network
  before calling `authenticate_request` (`app.api.deps.get_caller`).
* Replacing a factor (rotation) clears `mfa_verified_at` on every other live session.
* Rate-limit `login`, `register`, `refresh`, MFA endpoints with `app.ratelimit.RateLimiter`.
* Audit event types emitted: `auth.register`, `auth.bootstrap_admin`, `auth.login`, `auth.lockout`,
  `auth.refresh`, `auth.refresh_reuse` (critical), `auth.logout`, `auth.token`, `auth.session`,
  `auth.mfa_enroll`, `auth.mfa_activate`, `auth.mfa_verify`, `auth.mfa_disable`, `auth.password_change`,
  `auth.session_revoke`; denials of the API gates: `auth.me`, `auth.session_list`, `auth.session_revoke`,
  `auth.password_change` (outcome `denied`). `details` keys used: `reason`, `mfa`, `failed_count`,
  `lockout_seconds`, `sessions_revoked`, `sessions_kept`, `reuse_suspected`, `obligations`, `kind`, `scope`,
  `count`, `window_seconds` — the audit privacy allow-list has these (`container.EXTRA_AUDIT_DETAILS`).

## Implemented
* Argon2id (t=3, m=64 MiB, p=4; RFC 9106 option 2, above OWASP minimum), NFKC normalisation, rehash on
  login when parameters change, dummy verification for unknown/locked/disabled users.
* Password policy: min length (settings), max 256, not containing the username, embedded common-password
  deny-list (~180 entries), single-repeated-character rejection.
* TOTP (RFC 6238, SHA-1, 6 digits, 30 s, ±1 step) via pyotp; seed only KMS-encrypted with context
  `{"user_id", "purpose": "totp"}`; activation needs a valid code; replay guard via `mfa_last_counter`
  with an atomic compare-and-set (a code, or any older code, cannot be reused). MFA failures count towards
  lockout; reaching the limit during step-up also revokes the guessing session. Activating MFA revokes the
  user's other (password-only) sessions [**changed by ADR-0010**: activation no longer revokes other
  sessions nor verifies the current one]; disabling requires a valid code.
* Access tokens: compact JWS built here, signed by `kms.sign(purpose=TOKEN_SIGNING)`; algorithm pinned to
  EdDSA before any crypto (rejects `none`, `HS256`, ...); header limited to alg/typ/kid; `kid="<key_id>:<version>"`
  for rotation; exactly the 8 claims; `exp` strict (no leeway), `iat` ≤ 5 s in the future; lifetime longer
  than `access_token_ttl_seconds` rejected; duplicate JSON keys rejected. Interoperable with PyJWT (tested).
* Refresh tokens: `secrets.token_urlsafe(32)`, stored as hex HMAC (`kms.mac(LOOKUP_HMAC)`), single use via
  atomic compare-and-set, rotated, expiry capped at the session's absolute expiry; reuse → session revoked
  (`refresh-reuse`) + critical audit event.
* Sessions: absolute + idle expiry (expired sessions are marked revoked), server-side revocation, optional
  IP binding (stores HMAC of the IP, IPv4-mapped IPv6 normalised), DB re-read of user + session per request.
* Lockout: `max_failed_logins` consecutive failures (password or TOTP) → `lockout_seconds`; correct
  passwords refused while locked; atomic counter increment.

## Not implemented / limitations
* No breach-corpus (HIBP) password check; only the embedded list.
* No WebAuthn/FIDO2, no recovery codes; losing the TOTP device needs an admin: `POST
  /api/admin/users/{id}/mfa-reset` (removes the factor, revokes sessions), then an enrolment code.
* **TOFU window (ADR-0010 residual).** A password stolen within `mfa_self_enroll_window_seconds` of
  registration, before the owner enrols, lets the thief enrol their own factor and then step up with it.
  Detective (WARNING `auth.mfa_enroll`/`auth.mfa_activate` with the source network) and recoverable (admin
  reset), not prevented. Demonstrated by `tests/security/test_s11_s15_unc5537.py::test_s11_stated_limit_tofu_window`.
* The bootstrap-admin enrolment exception has no time limit while no other admin holds a factor; enrol the
  bootstrap admin at first login (the default `require_mfa_for_login=true` leaves it nothing else to do).
* Admin enrolment codes are a privileged path: an admin (with fresh MFA) can let any non-admin account
  establish a factor. Issuance and use are audited at WARNING; the code must reach the user out of band.
* Bearer tokens only (no DPoP/mTLS). A stolen access token works until expiry (≤ 5 min) unless the session
  is revoked.
* Lockout is per account and can be abused to lock a victim out for `lockout_seconds` (time-boxed by design).
  Per-IP throttling must come from the rate limiter at the API layer. Up to `max_failed_logins` attempts can be
  in flight at once; a correct password resets the counter, so 4 wrong + 1 right + 5 wrong is possible (the
  attacker then already had the password).
* (Corrected in Phase 6) Usernames are stored lower-case and `app/models.py` has a functional unique
  index on `lower(username)`, so concurrent `Alice`/`alice` registrations cannot both succeed. Verified by
  `tests/integration/app/test_app_auth.py::test_usernames_are_case_insensitive_and_unique_under_race` and
  `::test_username_uniqueness_is_enforced_by_the_database`.
* `login` timing equality is about Argon2 work; DB query differences for unknown users are not padded.
* Expired-token presentations are not audited (routine); all other token failures are (`auth.token`).

## Tests
ADR-0010 / F1 / F2 unit tests: `tests/unit/auth/test_auth_mfa_enrollment.py`; HTTP level:
`tests/integration/app/test_app_auth.py` (`test_default_policy_requires_mfa_and_activation_needs_a_new_login`,
`test_admin_enrolment_code_flow`, `test_admin_mfa_reset_revokes_sessions`) and `tests/security/test_s11_s15_unc5537.py`.

Command (from `backend/`): `.venv/bin/python -m pytest tests/unit/auth tests/unit/policy -q`
Last run (after the independent-review fixes): `418 passed in 3.43s` (auth alone: `79 passed`). With the
rate limiter (`tests/unit/auth tests/unit/policy tests/unit/test_ratelimit.py`): `424 passed in 2.81s`.
Review regression tests (HTTP level): `tests/review/test_review_auth.py`.
Test fakes: `tests/unit/_fakes_auth.py` (in-memory KMS with Ed25519/AES-GCM/HMAC, recording AuditSink, FakeClock).
