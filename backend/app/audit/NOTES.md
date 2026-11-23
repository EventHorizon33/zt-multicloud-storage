# app/audit — Phase 5 notes

Privacy-aware, tamper-evident audit logging (ADR-0006, ADR-0007). Library
code only, with no routers. Imports only `app.contracts`, `app.config`,
`app.errors` and its own package. It does not import `app.kms` or `app.storage`.

## Files

| File | Content |
|---|---|
| `__init__.py` | `build_audit_service` factory and re-exports |
| `service.py` | `AuditService`: record, pseudonyms, append locking, checkpoints, anchors, `verify_chain`, query delegation |
| `privacy.py` | allow-list, deny scan, value redaction, IP generalisation |
| `chain.py` | canonical JSON, record hash, timestamp format |
| `models.py` | separate declarative base `AuditBase`, tables, `make_audit_engine`, `begin_write` |
| `query.py` | `AuditQuery`: search, get_event, stats, recent_security_events, export_ndjson |
| `retention.py` | `apply_retention` |
| `records.py` | value types (`AuditRecord`, `Checkpoint`, `Finding`, `VerificationReport`, `RetentionResult`, `AuditContext`) |
| `errors.py` | `AuditError` (500), `AuditWriteError` (503), `AuditIntegrityError` (409), all `AppError` subclasses |

## Public API (for the integrator)

```python
from app.audit import (build_audit_service, AuditService, AuditContext, AuditRecord,
    Checkpoint, Finding, VerificationReport, RetentionResult, AuditError, AuditWriteError,
    AuditIntegrityError, GLOBAL_ALLOWED_DETAIL_KEYS, EVENT_ALLOWED_DETAIL_KEYS,
    filter_details, generalise_ip, AnchorStore)

build_audit_service(settings: Settings, kms: KeyManagementService,
                    anchor_store: AnchorStore | None = None,
                    clock: Callable[[], datetime] | None = None, *,
                    extra_allowed_details: Mapping[str, Iterable[str]] | None = None) -> AuditService
    # engine on settings.audit_database_url (its own DB) + create_all of the audit tables

class AnchorStore(Protocol):            # implemented by the storage layer (phase 6 adapter)
    def put_anchor(self, key: str, data: bytes) -> dict[str, bool]: ...       # provider -> stored
    def get_anchor(self, key: str) -> dict[str, bytes | None]: ...             # provider -> copy
    def list_anchors(self, prefix: str) -> dict[str, list[str]]: ...           # provider -> keys

class AuditService:                     # satisfies contracts.AuditSink
    def record(self, *, event_type, action, outcome, actor_id=None, actor_role=None,
               resource_type=None, resource_id=None, reason=None, severity=Severity.INFO,
               details=None, request_id=None, source_ip=None) -> AuditRecord  # (seq, id, ts, hash, prev_hash)
    def pseudonym_for(self, user_id: str) -> str            # "u_" + hex(HMAC)[:32]
    def create_checkpoint(self, kind: str = "manual", *, audit_context: AuditContext | None = None) -> Checkpoint
    def list_checkpoints(self, limit: int = 100) -> list[Checkpoint]          # newest first
    def verify_chain(self, *, from_seq: int | None = None, to_seq: int | None = None,
                     check_anchors: bool = True, batch_size: int = 1000,
                     max_findings: int | None = None,
                     audit_context: AuditContext | None = None) -> VerificationReport
    def apply_retention(self, now: datetime | None = None, *,
                        audit_context: AuditContext | None = None) -> RetentionResult
    def search(self, *, actor=None, event_type=None, action=None, resource_id=None,
               resource_type=None, outcome=None, severity=None, min_severity=None,
               ts_from=None, ts_to=None, request_id=None, limit=100, offset=0,
               order="desc") -> tuple[list[dict], int]
    def get_event(self, seq: int) -> dict | None
    def stats(self, since: datetime | str | None = None) -> dict
    def recent_security_events(self, limit: int = 50) -> list[dict]
    def export_ndjson(self, from_seq: int | None = None, to_seq: int | None = None) -> Iterator[str]
    engine: Engine (property); close(); checkpoint_failures: int; anchor_failures: int

@dataclass(frozen=True) class AuditContext: actor_id, actor_role, request_id, source_ip (all optional)
@dataclass VerificationReport: ok, events_checked, first_seq, last_seq, head_hash,
    checkpoints_checked, anchors_checked, findings: list[Finding(type, seq, detail)],
    findings_truncated, duration_ms; .to_dict(), .finding_types()
@dataclass(frozen=True) RetentionResult: deleted, kept, new_first_seq, checkpoint_seq; .to_dict()
@dataclass(frozen=True) Checkpoint: id, seq, head_hash, ts, kind, key_id, key_version,
    signature (hex), event_count, first_seq, anchors; .payload(), .document(), .to_dict()
```

Integration notes:
* **Error behaviour.** `record()` raises `AuditWriteError` if the event was not committed. The caller must abort the operation. It raises `ValueError` for an unknown outcome or severity, or for an empty event_type or action. These are programming errors. It never raises because of *content*. Sensitive content is redacted or dropped instead.
* **Search errors.** `search` and `recent_security_events` raise `ValueError` on bad limit, offset, order or severity. Map that to 422. `limit` must be 1..1000. `event_type` is an exact match, or a prefix match when it ends in `*` or `.`. Note that `"auth*"` also matches `authz.*`, so use `"auth.*"` for the auth family. `ts_from` is inclusive and `ts_to` is exclusive. Both take a datetime or an ISO string.
* **"My events".** Use `search(actor=svc.pseudonym_for(subject.user_id))`.
* **Re-identification.** There is no reverse table. To re-identify, an admin computes `pseudonym_for(candidate_user_id)`, and the API should audit that lookup itself, for example as `audit.reidentify` with `target_user` set to the pseudonym.
* **`target_user` in details.** It must already be a pseudonym. Call `pseudonym_for` before passing it.
* **Housekeeping events.** Pass `audit_context=` to `create_checkpoint`, `verify_chain` and `apply_retention`. The service then records `audit.checkpoint`, `audit.verify` or `audit.retention`. Each is recorded after the operation, with outcome success, failure or error. A failed verification is recorded with severity `critical`. Checkpoint creation itself is never an event, so there is no recursion.
* **Timestamps.** `clock` must return aware UTC datetimes. Naive datetimes are treated as UTC.

## Storage (separate audit DB)

`audit_events`: seq INTEGER PK (assigned by the service, +1), id (uuid4 hex), ts TEXT, event_type, action, outcome, severity, actor (pseudonym or NULL), actor_role, resource_type, resource_id, reason, details (canonical JSON TEXT), request_id, source_net, prev_hash, hash. Indexes: ts, actor, event_type, resource_id, outcome, severity, request_id, hash. The hash index is used to diagnose reordering.

`audit_checkpoints`: id, seq, head_hash, ts, kind (`periodic`|`manual`|`retention`), key_id, key_version, signature (hex), event_count, first_seq, anchors (JSON provider → bool; `{"_error": false}` if the anchor store raised).

There is no state table. The head is `MAX(seq)`. If the table is empty, the head falls back to the latest retention checkpoint, and then to genesis (0, 64 zeros).

**Appends.** Each append takes a process `RLock` and then a DB write lock. On SQLite the engine runs the driver in autocommit mode and `begin_write` issues `BEGIN IMMEDIATE`. On PostgreSQL `begin_write` issues `SELECT pg_advisory_xact_lock(<const>)`. Inside that, the append reads the head, inserts, and commits in its own transaction. A seq primary-key collision is retried up to 5 times. Any other DB error becomes `AuditWriteError` with no chained cause, because DBAPI errors can carry the statement parameters.

**Durability.** SQLite runs with WAL and `synchronous=FULL`. Every append is fsynced, about 740–950 appends/s on the test machine across runs.

## Formats

* **Timestamp.** `YYYY-MM-DDTHH:MM:SS.ffffffZ`, fixed width, UTC. It is stored as TEXT, so the hashed bytes are exact and string order equals time order.
* **Canonical JSON.** `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)`.
* **Record hash.** `hash = sha256(bytes.fromhex(prev_hash) + canonical_json({all 16 columns except hash}).encode("ascii")).hexdigest()`. The 16 columns include `seq` and `prev_hash`. `details` is hashed as its stored JSON *string*. Genesis `prev_hash` is `"0"*64`.
* **Checkpoint payload.** The signed bytes are `canonical_json({"v":1,"seq","head_hash","ts","event_count","first_seq","kind"})`, signed with `kms.sign(payload, purpose=AUDIT_SIGNING)` (Ed25519). `event_count = seq - first_seq + 1`, where `first_seq` is the first retained seq at checkpoint time.
* **Anchor document.** `canonical_json({"v":1,"alg":"Ed25519","payload":<payload string>,"signature":<hex>,"key_id","key_version"})`. It is written to every provider at `anchors/audit/{log_id}/checkpoint-{seq:012d}.json`, which covers periodic and manual checkpoints. Retention checkpoints are written to `anchors/audit/{log_id}/retention-{seq:012d}.json` instead (a retention checkpoint can share a seq with a periodic one and must not overwrite it).
* **Anchor namespace (ADR-0006 amendment, finding F4).** `log_id = sha256(SubjectPublicKeyInfo PEM of the audit-signing key, version 1)[:16]` (lowest available version if v1 cannot be read), exposed as `AuditService.log_id`. It comes from the KMS, not from the audit DB: stable across signing-key rotation, different for every deployment/keystore, and wiping or replacing the audit DB does not move the log to a fresh namespace. Until the fix the key had no `{log_id}/` segment, so two deployments sharing a bucket overwrote each other's anchors at equal sequence numbers (reported as `anchor-mismatch`, `ok=false`, without any tampering). Verification lists only `anchors/audit/{log_id}/` and ignores everything else, including **legacy un-namespaced anchors**: after an upgrade, DB checkpoints anchored under the old keys report the informational `anchor-missing` until new checkpoints are written.
* **Export.** `export_ndjson` yields one line per event. Each line is the canonical JSON of the stored row including `hash`, so a line can be re-verified offline with the formula above.

## Periodic checkpoints

A periodic checkpoint is created when `head_seq - last_checkpoint_seq >= settings.audit_checkpoint_every` (0 disables). It is created inside the process lock, right after the event commits, in its own transaction. The anchor upload happens after the lock is released.

If signing or the checkpoint insert fails, the error is not raised, because the event is already committed. Instead `checkpoint_failures` is incremented and the next append retries. Anchor failures are never raised either: they are recorded per provider in the row, and `anchor_failures` is incremented.

## Privacy filter

* **Actor.** `actor = "u_" + kms.mac(user_id.encode(), purpose=AUDIT_PSEUDONYM).hex()[:32]`. The raw user id is never stored.
* **details keys.** A top-level key is kept only if it is on the allow-list and its *name* matches no deny pattern. At most 64 keys are kept, and canonical details are capped at 8 KiB.
* **details values.** Values may be `str/int/float/bool/None`, or one level of list or dict of those. A list or dict keeps at most 50 items. Nested dict keys get the same deny-name check. NaN and inf are dropped, as are ints of 2^63 or more and bytes or other objects.
* **Strings.** A string is replaced by `"[REDACTED]"` if it contains any of:
  * a JWT
  * a `Bearer `/`Basic ` credential
  * a PEM header
  * an email address
  * a `password=`/`token:`-style assignment
  * a key-like blob: 40 or more base64/hex characters that are pure hex, or that mix character classes with Shannon entropy ≥ 3 bits/char

  Otherwise the string is truncated to 256 characters. The scan runs before truncation.
* **Dropped entries.** Dropped entries, at any level, are counted in `_dropped`. Their key names are never stored.
* **`reason`.** The same value scan applies, with truncation at 512 characters.
* **Label columns.** `event_type`, `action`, `actor_role`, `resource_type`, `resource_id` and `request_id` get the value scan *without* the blob heuristic, because resource ids are opaque random hex. They are truncated to their column sizes.
* **Source IP.** IPv4 is generalised to `/audit_ip_prefix_v4` and IPv6 to `/audit_ip_prefix_v6`. IPv4-mapped IPv6 is treated as IPv4. `[v6]` brackets and `%zone` suffixes are accepted. Anything else, including `host:port`, becomes NULL.

`GLOBAL_ALLOWED_DETAIL_KEYS` (exported):
reason, reasons, policies, obligations, chunk_index, chunk_count, chunk_size, size_bytes, bytes, providers, provider, failed_providers, replicas, attempts, retries, classification, file_status, verified, corrupt, missing, repaired, role, old_role, new_role, session_id, mfa, method, target_user, changed_keys, old, new, key_purpose, key_version, old_version, new_version, count, window_seconds, threshold, latency_ms, duration_ms, error_class, state, previous_state, http_status, ok, mode, kind, seq, first_seq, last_seq, deleted, kept.

`EVENT_ALLOWED_DETAIL_KEYS` (exported):
* `audit.verify`: events_checked, checkpoints_checked, anchors_checked, finding_types
* `audit.checkpoint`: event_count

Extra per-event-type sets can be passed with `extra_allowed_details={"file.*": {...}}`. Those keys still go through the deny scan.

Deny name patterns are matched as substrings of the normalised key name: password, passwd, passphrase, pwd, secret, token, authorization, cookie, credential, bearer, jwt, dek, kek, private_key, api_key, access_key, key_material, totp, otp, seed, filename, file_name, username, user_name, email, content, plaintext.

## Verification: what `verify_chain` detects

Events are streamed in keyset-paginated batches (default 1000). The whole table is never loaded. All checkpoint rows are loaded; there is one per N events. Every finding is reported, not just the first.

`ok` is true only if there are no findings other than the informational ones (`anchor-missing`, `anchor-unavailable`).

| type | meaning |
|---|---|
| `record-modified` | stored hash ≠ recomputed hash (any field edited, seq changed, malformed prev_hash) |
| `chain-broken` | prev_hash ≠ stored hash of the predecessor (catches "edit + recompute own hash" at the next record; deletions; insertions) |
| `reordered` | on a broken link, the record's prev_hash equals the hash of a record at a *different* position (rows swapped/moved) |
| `sequence-gap` | missing seq numbers (deleted records) |
| `sequence-out-of-order` | defensive; cannot occur with ORDER BY on the PK |
| `timestamp-regression` | ts earlier than predecessor's (fails verification; clock skew or tampering) |
| `checkpoint-signature-invalid` | DB checkpoint signature or payload does not verify (edited head_hash/seq/signature) |
| `checkpoint-mismatch` | a trusted checkpoint's head_hash ≠ chain hash at that seq (whole tail rewritten with a valid chain) |
| `checkpoint-missing` | a validly signed anchor exists for a seq in the retained range, but its DB checkpoint row is gone |
| `truncated` | a trusted checkpoint (DB **or anchor**) references a seq beyond the current head, or the log is empty while non-retention checkpoints exist |
| `anchor-mismatch` | a provider copy is malformed, fails its signature, differs from the DB checkpoint, or providers disagree |
| `anchor-missing` | (informational) some/all providers lack a copy of a DB checkpoint |
| `anchor-unavailable` | (informational) listing/reading anchors raised |
| `genesis-invalid` | first retained record does not link to genesis (seq 1) or to a signed retention checkpoint at exactly seq-1 → records deleted outside retention |

**Anchor-based detection.** Anchors are discovered with `list_anchors("anchors/audit/{log_id}/")` across all providers (keys of other logs are neither trusted nor reported), plus the keys of the DB checkpoints. Every validly signed anchor is added to the trusted checkpoint set. So deleting both the tail events and all checkpoint rows is still reported as `truncated`, provided an anchor exists. This is tested, including deleting every event.

Non-retention anchors below the first retained seq are expected leftovers of retention and are ignored. Retention anchors always count, so deleting the retention checkpoint row is recovered from its anchor and reported as `checkpoint-missing`.

**Partial ranges.** With `from_seq`/`to_seq`, the predecessor of the first record is looked up so the link can still be checked. Truncation is always judged against the global head.

**Key rotation.** Each checkpoint stores `key_id`/`key_version` and is verified with that version. This is tested across two rotations.

### Stated limits

* **Signing key plus every copy.** An attacker who holds the audit **signing key** and can rewrite the audit DB **and every anchor copy** can rewrite history undetectably.
* **Events after the last checkpoint.** These can be truncated or consistently rewritten without detection until the next checkpoint. The window is `audit_checkpoint_every` events. This is tested in `test_rewrite_after_last_checkpoint_is_the_stated_limit`.
* **No anchor store.** Without an anchor store, deleting the tail *and* the checkpoint rows together is undetectable (the test asserts this with `check_anchors=False`). Deleting everything including the retention checkpoint rows looks like an empty, new log.
* **Anchor namespace = signing key.** An attacker who can make the deployment use a different audit-signing keystore (new KMS) also moves new anchors to a new namespace; the old namespace still holds the old anchors, which an investigator can verify with the old public key, but `verify_chain` of the new deployment does not look there.
* **Timestamps.** `ts` comes from the backend clock. The chain proves order and integrity, not wall-clock truth.
* **Locking in other deployments.** Cross-process serialisation relies on SQLite's file lock or the PostgreSQL advisory lock. The PostgreSQL path is implemented but **not tested** here, because no server was available. Other dialects rely on PK-collision retry only.
* **Allow-list leaks.** The deny scan is heuristic. An allow-listed field carrying a short secret, such as a 6-digit TOTP code under `count`, is not recognisable. Callers must still pass only allow-listed, non-sensitive values.

## Retention

`apply_retention(now)` works as follows.

1. It computes `cutoff = now − audit_retention_days`. A value of `<= 0` disables retention and returns `deleted=0`.
2. It finds the cut point S: the last seq such that **every** event with seq ≤ S is older than the cutoff. A younger event stops the cut.
3. It verifies the chain up to S. If that fails, it **refuses** with `AuditIntegrityError`, so retention can never launder tampering.
4. In one transaction it signs and inserts a `retention` checkpoint at S (head_hash = hash of record S). In the same transaction it deletes events with seq ≤ S and deletes non-retention checkpoints with seq ≤ S. Retention checkpoints are kept.
5. It anchors the retention checkpoint.

After retention, `verify_chain` requires the first retained record's prev_hash to equal the signed retention head. Deleting one more early record is reported as `genesis-invalid` (tested).

Appends after a full prune continue from the retention checkpoint head. Anchors on providers are never deleted by retention; they hold only hashes and sequence numbers.

## Tests

The tests attack the audit DB through a raw `sqlite3` connection. Fakes live in `tests/unit/audit/_fakes.py`:
* `FakeKMS`: real Ed25519 and HMAC-SHA256, with versioned keys and rotation
* `FakeAnchorStore`: three dict-backed providers, with per-provider down and raise-on-put switches
* `ManualClock`

Command and result of the last run:

```
cd backend && .venv/bin/python -m pytest tests/unit/audit -q
179 passed in 9.21s
```

The 179 tests break down as follows (parametrised cases are counted individually):

| File | Test functions | Coverage |
|---|---|---|
| test_audit_chain | 7 | |
| test_audit_tamper | 18 | |
| test_audit_privacy | 14 | 110 cases with parametrisation |
| test_audit_checkpoints | 10 | |
| test_audit_retention | 13 | |
| test_audit_query | 9 | 15 cases |
| test_audit_robustness | 6 | concurrency 16 threads × 50 → seq 1..800 contiguous, verify ok; two service instances on one DB → 400 events, verify ok; DB failures; perf |

**Measured performance** (printed by `test_verify_20k_events_performance` in the run above):
* 1000 real `record()` calls: 1.35 s (739/s, fsync per event)
* `verify_chain` over 20 000 events + 190 checkpoints + 570 anchor copies: **0.54 s**

That chain was bulk-built in 100-row transactions with a signed, anchored checkpoint after each batch. An earlier run that appended all 20 000 events through `record()` took 24.7 s to append and 0.55 s to verify. No tight time bound is asserted.

## Not implemented

* A PostgreSQL integration test for the advisory-lock path.
* A REST API and UI. Those are phase 6 and 7.
* (Done in Phase 6) A storage-layer `AnchorStore` adapter (`OrchestratorAnchorStore`).

## Ambient request context (finding F5)

`app/audit/context.py`: a `ContextVar` holding a small mutable `_RequestAuditState`. The API middleware calls
`begin_request(request_id, client_ip)` / `end_request(token)` around every request and `get_caller` calls
`bind_actor(user_id, role)`. `AuditService.record` fills `request_id`, `source_ip` and the actor (and its
role) from `current_audit_context()` when the caller passed `None`; **explicit values always win**. Because the
holder is shared by every copy of the context, an actor bound in one FastAPI worker thread (the dependency)
is visible in another (the endpoint). Own thread pools must propagate with `contextvars.copy_context().run`
(the storage orchestrator and `DeadlineRunner` do). `suspended()` disables filling for events that must not
be attributed to the current request (the rate-limit summary). Background threads have no context.
Tests: `tests/unit/audit/test_audit_context.py`, `tests/security/test_s05_s07_data_integrity.py::test_s05_storage_integrity_events_carry_the_request_context`.

## Rate-limit audit (finding F6)

`app/ratelimit.RateLimitAuditor` (wired in `container.py`, called from `api/deps.rate_limit`): the first 429
per (scope, key) per 60 s window → `security.rate-limited` (denied, WARNING, `details {scope, count: 1,
window_seconds, kind: "first"}`, request id + source, actor for user-keyed scopes); later 429s in the window
are counted and written as one `kind: "summary"` event (outside any request context) when the window is
over (next rejection of that key, the maintenance loop's `flush()`, or `flush(force=True)` at shutdown).
State is bounded (`max_keys`, oldest windows summarised first) and per process. The limiter key itself is
never put in `details`. Tests: `tests/unit/test_ratelimit_audit.py`,
`tests/security/test_s10_brute_force.py::test_s10_rate_limit_rejections_are_audited`.
