# app/policy — zero-trust PDP, PEP, policy settings (Phase 2)

## Public API

```python
from app.policy import PolicyDecisionPoint, PolicyEnforcementPoint, PolicyConfig, PolicyStore, describe_policies

PolicyDecisionPoint(config: PolicyConfig | None = None)
  .evaluate(subject: Subject, action: Action, resource: Resource, context: RequestContext,
            config: PolicyConfig | None = None) -> Decision        # pure: no DB, no I/O, no clock
  .describe_policies() -> list[dict]     # id, description, effect, stage, actions, roles, condition, reason
  .with_config(config) -> PolicyDecisionPoint

PolicyEnforcementPoint(pdp: PolicyDecisionPoint, audit: AuditSink, policy_store: PolicyStore)
  .enforce(db, subject, action, resource, context) -> Decision     # audits; raises AccessDenied on deny
  .check(db, subject, action, resource, context, *, audit: bool = False) -> Decision   # never raises

PolicyConfig (frozen dataclass): mfa_required_actions: frozenset[Action], mfa_required_classification:
  Classification, mfa_step_up_max_age_seconds: int, max_session_age_seconds: int, require_mfa_for_login: bool,
  max_downloads_in_window: int, max_download_bytes_in_window: int, window_seconds: int, block_seconds: int
  PolicyConfig.from_settings(settings) ; .to_dict() -> JSON-safe dict

PolicyStore(*, settings: Settings, audit: AuditSink, clock: Callable[[], datetime])
  .defaults -> PolicyConfig
  .load(db) -> PolicyConfig ; .version(db) -> int
  .load_report(db) -> (PolicyConfig, version, ignored_keys)       # invalid stored rows fall back to default
  .update(db, changes: Mapping[str, Any], *, actor_id, actor_role=None, request_id=None, source_ip=None)
        -> PolicyConfig                                              # validate, bump version, audit, commit
```

`AccessDenied` raised by `enforce` has `.reasons` (machine codes), `.obligations` and `.decision`.
Use `obligations` to tell the client to step up (`step-up-mfa`) or enrol (`enroll-mfa`).

The PEP loads the policy from the `PolicyStore` on every call, so changes apply to the next request.
`authz.decision` audit events: outcome `success`/`denied`, severity `info`/`warning`,
`details={"reasons": [...], "policies": [...], "obligations"?: [...]}`, `resource_type/resource_id` from the
Resource, `request_id`/`source_ip` from the context. `policy.change` events: severity warning,
`details={"changes": {key: {"old", "new"}}, "version": n}` (failure: `{"reasons": [...]}`).
The audit privacy allow-list needs these keys.

Note (finding F2): the `network-not-allowed` guard covers only PDP-gated actions. `/api/auth/*` is not
PDP-gated, so `AuthService` applies the same allow list itself (`AuthService.network_allowed`, which
reuses `pdp.ip_allowed`) on login, refresh, password change and every MFA endpoint, and (review L1) on
`/me` and session list/revoke. Likewise the restricted-session rule (`mfa-enrollment-required` here) is
mirrored for `/api/auth/sessions*` and password change by `AuthService.require_mfa_session` (review M5).

## Evaluation order
1. **Guards** (deny-only, any action): `user-inactive`, `network-not-allowed` (non-empty `allowed_cidrs` and
   source IP missing/unparseable/outside; IPv4 + IPv6, IPv4-mapped IPv6 normalised, malformed CIDRs never
   match), `session-too-old`, `mfa-enrollment-required` (when `require_mfa_for_login` and the session is not
   MFA-verified; only `security:read` and `policy:read` remain allowed; `require_mfa_for_login` defaults to
   **true** since ADR-0010), `download-rate-exceeded`
   (`file:read` and `context.download_blocked`).
2. **Constraints** (deny-only): `not-owner`, `admin-no-content-access`, `classification-missing`
   (fail closed), `insufficient-clearance`, `mfa-required`, `mfa-stale`, `file-not-available`.
3. **Allow rules.** Allow iff ≥1 allow rule matched and no deny matched. Otherwise deny with **all** reasons;
   `default-deny` when nothing allowed and nothing more specific applies. `step-up-mfa` obligation is set
   only when an allow rule matched and the only reasons are `mfa-required`/`mfa-stale`.

## Permission model

Ownership columns apply to a `Resource(type="file", owner_id=..., shared_with_subject=...)`.
"✔" = allowed by RBAC/ownership (still subject to guards and the ABAC/MFA constraints below).

| Action | user | auditor | admin |
|---|---|---|---|
| file:create, file:list (resource type `file`) | ✔ | ✔ | ✔ |
| file:read-metadata | owner, grantee | owner, grantee | **any file** |
| file:read | owner, grantee | owner, grantee | owner, grantee; other → `admin-no-content-access` |
| file:delete, file:share | owner | owner | owner; other → `admin-no-content-access` |
| file:verify, file:repair | owner | owner | **any file** (no plaintext leaves) |
| audit:read-own, dashboard:read, storage:read, policy:read, security:read | ✔ | ✔ | ✔ |
| audit:read-all, audit:verify, kms:read | – | ✔ | ✔ |
| user:list | – | – | ✔ |
| user:manage, policy:write, kms:rotate, storage:admin, audit:checkpoint, audit:retention | – | – | ✔ |

Non-owners without a share get `not-owner`; everything not listed is `default-deny`.
Auditors lost `user:list` in the independent review (finding M1): the user directory let them map every
audit pseudonym to a username without the audited re-identification path. Auditors work with pseudonyms.

ABAC / contextual constraints on top:

| Constraint | Applies to | Deny reason |
|---|---|---|
| classification.rank > clearance.rank | file:read, file:read-metadata, file:create | `insufficient-clearance` |
| classification is None | same (file resources) | `classification-missing` |
| fresh MFA (`mfa_verified` and age ≤ `mfa_step_up_max_age_seconds`) | `mfa_required_actions` (default: file:delete, file:share, user:manage, policy:write, kms:rotate, audit:retention, storage:admin) and file:read with classification ≥ `mfa_required_classification` (default confidential) | `mfa-required` / `mfa-stale` + `step-up-mfa` |
| status == "committed" | file:read | `file-not-available` |

`PolicyStore` validation: unknown keys rejected; integer ranges (step-up age 30 s–24 h, session age
5 min–30 d, downloads ≥ 1, window 10 s–7 d, block 0–30 d); booleans strict; actions/classification must be
valid enum values; safety floor: `policy:write` can never be removed from `mfa_required_actions`.

## Integration notes
* Build the `Resource` for files from the DB row: `classification=Classification(row.classification)`,
  `status=row.status`, `shared_with_subject` from an un-revoked `FileShare`. For `file:create` pass the
  intended classification (otherwise `classification-missing`). For list endpoints, filter with
  `pep.check(...)` per row and return 404 for both unknown and denied IDs (THREAT_MODEL).
* The download thresholds in `PolicyConfig` are for app/detection, which sets
  `RequestContext.download_blocked`; the PDP itself only reads the flag.
* `app/ratelimit.py`: `RateLimiter(*, clock=time.monotonic, max_buckets=100_000, sweep_every=1024)`,
  `.check(scope: str, key: Hashable, limit_per_minute: int) -> None` raises `RateLimited` with
  `.retry_after_seconds: int`; `.reset(scope=None)`. **Per-process** state: N workers ⇒ N× the limit,
  reset on restart. Memory bounded: fully-refilled buckets are swept, LRU eviction above `max_buckets`
  (can only make limiting more lenient for evicted keys).

## Not implemented / limitations
* Rules are code-defined data; only the `PolicyConfig` parameters are runtime-editable (no rule editor).
* No resource-type validation for non-file actions (e.g. `audit:read-all` is decided on role alone; the
  API must scope data, e.g. own events for `audit:read-own`).
* Policy rows are not integrity-protected (a DB writer can change them; invalid values are ignored, valid
  but weaker values are not detected except via the audit trail of `policy.change`).
* No distributed rate limiting.

## Tests
Command (from `backend/`): `.venv/bin/python -m pytest tests/unit/auth tests/unit/policy -q`
Last run (after the independent-review fixes): `418 passed in 3.43s` (policy alone: `339 passed in 0.66s`,
of which 276 are the Role × Action × {owner, grantee, other, non-file} matrix; auditor `user:list` is now
expected to be denied). Rate limiter: `.venv/bin/python -m pytest tests/unit/test_ratelimit.py -q` →
`6 passed in 0.01s`.
