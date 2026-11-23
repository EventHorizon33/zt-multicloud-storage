# app/storage — Phase 4 notes

Multi-cloud storage abstraction and orchestration. This layer only ever sees
opaque object keys (chunk ids) and ciphertext bytes. It holds no keys, no user
ids, no filenames, and it never puts object contents into exceptions, audit
events or metrics. All code is synchronous.

## What the tests prove, and what they do not

The emulator tests run the **real vendor SDKs** (boto3, azure-storage-blob,
google-cloud-storage) against **local emulators** (moto server, Azurite,
gcp-storage-emulator). They prove the adapters work against those emulators.
They do **not** prove behaviour against real AWS S3, Azure Blob Storage or
Google Cloud Storage: real IAM, real network latency/throttling, real
consistency behaviour, TLS, and real error payloads were not exercised. No
cloud account was used.

## Files

| File | Content |
|---|---|
| `__init__.py` | `build_providers`, `build_orchestrator`, re-exports |
| `_common.py` | key/prefix/metadata validation, message sanitisation, `InvalidObjectKey`, `StorageConfigError` |
| `s3.py` | `S3Provider` (boto3) |
| `azure.py` | `AzureBlobProvider` (azure-storage-blob) |
| `gcs.py` | `GCSProvider` (google-cloud-storage) |
| `memory.py` | `MemoryProvider` — **unit tests only** |
| `faults.py` | `FaultInjectingProvider` — demos/tests only |
| `retry.py` | `RetryPolicy`, `call_with_retry`, `DeadlineRunner` |
| `health.py` | `HealthMonitor` (passive + active health, circuit breaker) |
| `placement.py` | `PlacementStrategy`, `RotatingPlacement`, `HashPlacement` |
| `metrics.py` | `StorageMetrics` (counters, latency histogram, Prometheus text) |
| `orchestrator.py` | `StorageOrchestrator` and its result and error types |

## Public API (exact signatures)

```python
# app.storage
def build_providers(settings, *, enable_fault_injection: bool | None = None) -> dict[str, StorageProvider]
def build_orchestrator(settings, *, providers=None, audit: AuditSink | None = None,
                       health: HealthMonitor | None = None, metrics: StorageMetrics | None = None,
                       enable_fault_injection: bool | None = None) -> StorageOrchestrator
```
`build_providers` maps `"aws-s3"` to `S3Provider`, `"azure-blob"` to `AzureBlobProvider` and `"gcs"` to
`GCSProvider`. It maps `"memory"` / `"memory-<x>"` to `MemoryProvider` **only when `settings.env == "test"`**.
Unknown or duplicate names and missing settings raise `StorageConfigError`. Its message names the
setting (e.g. `ZT_AZURE_CONNECTION_STRING`), never the value. When fault injection is enabled (the
argument, else `settings.enable_fault_injection`), every provider is wrapped in `FaultInjectingProvider`.
This is refused in production. `build_orchestrator` creates a `HealthMonitor` but does **not start** it;
call `orch.health.start()` / `orch.health.stop()` from app lifespan.

### Adapters (all implement `contracts.StorageProvider`)
```python
S3Provider(*, bucket, name="aws-s3", region="us-east-1", endpoint_url=None, access_key_id=None,
           secret_access_key=None, timeout_seconds=10.0, connect_timeout_seconds=None)
AzureBlobProvider(*, connection_string, container, name="azure-blob", timeout_seconds=10.0,
                  connect_timeout_seconds=None)
GCSProvider(*, bucket, name="gcs", project=None, endpoint_url=None, timeout_seconds=10.0,
            connect_timeout_seconds=None)
MemoryProvider(name="memory")
# each also has: .from_settings(settings, name=...) (cloud adapters) and .ensure_bucket() -> None
# StorageProvider methods: put(key, data, metadata=None) -> ObjectInfo; get(key) -> bytes;
#   delete(key) -> None (idempotent); exists(key) -> bool; stat(key) -> ObjectInfo;
#   list_keys(prefix="") -> Iterator[str] (lazy; errors surface while iterating); health() -> HealthStatus (never raises)
```
- **Timeouts.** The connect timeout is `min(timeout, 5s)` and the read timeout is `timeout_seconds`.
  Azure also sends a server-side timeout and GCS passes `(connect, read)` on every call.
- **SDK retries are disabled.** S3 uses `total_max_attempts=1`, Azure uses `retry_total=0`, and GCS
  passes `retry=None` on every call. The orchestrator owns retry.
- **S3 settings.** Path-style addressing is used when `endpoint_url` is set. Credentials come from
  settings when both are given, else the default AWS chain. Providing only one of the pair is a config error.
- **GCS credentials.** With `endpoint_url`, GCS uses anonymous credentials and `client_options={"api_endpoint": ...}`
  (emulator only). Otherwise it uses Application Default Credentials.
- **Error translation.** Errors map to `ObjectNotFound` / `ProviderUnavailable` / `ProviderTimeout` /
  `ProviderAuthError` / `StorageError`. Messages come from fixed templates plus the service error *code*
  and HTTP status or exception class name only. The SDK's own message is never used, so no URLs, signed
  query strings, headers or connection strings appear. A missing bucket or container is reported as a
  plain `StorageError("... bucket does not exist")`, never as `ObjectNotFound`.
- **Key validation.** Keys are checked before any request. These are rejected: non-string, empty,
  more than 256 chars, leading `/`, any `..`, backslash, ASCII/C1 control chars. The error never echoes
  the key. Metadata keys must match `[A-Za-z_][A-Za-z0-9_]{0,63}`; values are printable ASCII up to 1024 chars.
- **`ensure_bucket()` is never called implicitly.** It is meant for emulators and first-time setup.
- **`health()`.** S3 does HEAD bucket, Azure reads container properties and GCS does a bucket GET. It
  returns `healthy=False` with a sanitised error instead of raising.

### Fault injection
```python
FaultInjectingProvider(inner: StorageProvider, *, sleep=time.sleep)
  .set_mode(mode: str, **params) -> dict     # modes: none | unavailable | timeout(delay=0) |
                                              #   corrupt-reads | fail-n(n=1) | drop-writes | slow(delay=0.05)
  .clear() -> None; .mode -> str
  .status() -> {"provider", "mode", "params", "remaining_failures", "injected": bool,
                "fault_injection_enabled": True, "injected_failures_total": int}
```
Injected errors are `InjectedUnavailable` / `InjectedTimeout`. These are subclasses of the contract
errors with `injected = True`, and their message starts with `injected fault`. `HealthMonitor.snapshot()`
rows and `ProviderFailure` / `ReplicaAttempt` carry `injected`, so a demo fault can never be confused
with a real outage. Health probes do not consume the `fail-n` budget.

### Retry / deadline
```python
RetryPolicy(max_attempts=4, base_delay=0.2, max_delay=3.0, jitter=True)   # frozen dataclass
  .from_settings(settings); .backoff_cap(retry_number) -> float; .backoff(retry_number, rng=None) -> float
call_with_retry(fn, policy, *, sleep=time.sleep, on_retry: Callable[[int, BaseException, float], None] | None = None,
                rng=None) -> T
DeadlineRunner(max_workers=64).call(fn, timeout, *, provider=None, op="call") -> T; .shutdown()
```
- **Retry behaviour.** `max_attempts` includes the first try. The delay before retry k is drawn
  uniformly from `[0, min(max_delay, base_delay * 2**(k-1))]` (full jitter). Only `StorageError`s with
  `retryable=True` are retried. `ObjectNotFound` and `ProviderAuthError` are never retried, even when a
  subclass sets the flag.
- **Deadline caveat.** `DeadlineRunner` makes the caller give up after `timeout` and raises
  `ProviderTimeout`. Python cannot kill a thread, so the hung SDK call keeps running in its worker until
  the SDK's socket timeout ends it. The pool is bounded: a provider that hangs every call can occupy all
  workers, and later calls then queue and time out (fail closed). Time spent queued counts toward the deadline.

### Placement
```python
class PlacementStrategy(ABC):
    def targets(self, file_id: str, chunk_id: str, chunk_index: int,
                provider_names: Sequence[str], replication_factor: int) -> list[str]
RotatingPlacement()   # primary = names[(offset + i) % n], offset = SHA-256(file_id) % n, ring order after it
HashPlacement()       # rendezvous hashing, weight = SHA-256(chunk_id \0 provider)
placement_from_name("rotating" | "hash") -> PlacementStrategy
```
**Return shape.** `targets` returns every provider name exactly once:
- The first `replication_factor` entries are the preferred distinct replica targets in priority order;
  index 0 is the primary.
- The remaining entries are ordered fallback candidates.

The result is deterministic. It raises `ValueError` if `R > n`, `R < 1`, no providers are given, or a
name is duplicated.

### Health
```python
HealthMonitor(providers: Mapping[str, StorageProvider], interval=15.0, clock=time.monotonic, *,
              failure_threshold=3, cooldown_seconds=30.0, audit: AuditSink | None = None, wall_clock=utcnow)
  .record_success(provider, latency_ms=None, *, source="operation")
  .record_failure(provider, error, *, latency_ms=None, source="operation")
  .allow_request(provider) -> bool        # breaker gate; may move open -> half-open (one trial)
  .breaker_state(p) -> "closed"|"open"|"half-open"; .is_open(p); .is_healthy(p); .rank(p) -> 0|1|2
  .check_one(name) -> dict; .check_all() -> list[dict]; .start(); .stop(timeout=5.0); .running
  .snapshot() -> list[dict]  # provider, kind, healthy, state, latency_ms, consecutive_failures, last_error,
                             # last_checked (ISO), last_source, total_successes, total_failures, injected, fault_mode
```
- **Breaker.** The breaker opens after `failure_threshold` consecutive failures and stays open for
  `cooldown_seconds`. Then exactly one half-open trial is allowed. Success closes the breaker and
  failure re-opens it. A trial that never reports back is abandoned after another cool-down. A
  successful active probe also closes the breaker.
- **Audit events.** `storage.provider.health` is emitted on **transitions only**: the healthy flag
  flips, or the breaker opens or closes. Outcome `success` / `error`, severity `info` / `warning`,
  `resource_type="storage"`, `resource_id=<provider>`. Details keys: `provider, healthy, state,
  previous_state, consecutive_failures, injected`.
- **Audit failures.** If the audit sink raises during a health transition, the error is logged (class
  name only) and swallowed, so the prober keeps running.

### Metrics
```python
StorageMetrics()
  .inc(provider, op, counter, n=1)    # counters: attempts, successes, failures, retries, bytes
  .observe(provider, op, seconds); .get(provider, op, counter) -> int; .total(counter, provider=None) -> int
  .snapshot() -> {"counters": {provider: {op: {counter: n}}}, "latency": {provider: {op: {count, sum_seconds, buckets}}}}
  .render_prometheus() -> str         # zt_storage_<counter>_total, zt_storage_latency_seconds histogram
```

### Orchestrator
```python
StorageOrchestrator(providers: Mapping[str, StorageProvider], placement: PlacementStrategy,
                    retry_policy: RetryPolicy, health: HealthMonitor | None = None,
                    replication_factor: int = 2, min_write_replicas: int = 2,
                    audit: AuditSink | None = None, timeout_seconds: float | None = 10.0,
                    metrics: StorageMetrics | None = None, *, verify_writes: bool = True,
                    sleep=time.sleep, max_parallel: int = 16, deadline_workers: int = 64)
  .store_chunk(file_id, chunk_id, chunk_index, data, sha256_hex) -> StoreResult
  .fetch_chunk(chunk_id, replicas: Sequence[str], verify: Callable[[bytes], bool]) -> FetchResult
  .delete_chunk(chunk_id, replicas) -> DeleteResult
  .repair_chunk(chunk_id, chunk_index, file_id, good_data, sha256_hex, current_replicas, bad_replicas) -> list[str]
  .verify_replica(provider, chunk_id, sha256_hex) -> "ok"|"missing"|"corrupt"|"unavailable"
  .put_anchor(key, data) -> AnchorWriteResult
  .get_anchor(key) -> dict[str, AnchorRead]
  .list_anchors(prefix="") -> AnchorListing
  .health_snapshot() -> list[dict]; .provider_names -> list[str]; .provider(name) -> StorageProvider
  .set_fault(provider, mode, **params) -> dict    # raises FaultInjectionDisabled unless wrapped
  .fault_status() -> list[dict]; .metrics; .health; .close()

StoreResult(chunk_id, stored_on: list[str], failed: list[ProviderFailure], degraded: bool,
            failed_over: bool = False, attempts: int = 0)
ProviderFailure(provider, error_type, message, retryable, attempts=1, injected=False)
FetchResult(data: bytes, provider: str, attempts: list[ReplicaAttempt])
ReplicaAttempt(provider, outcome: "ok"|"missing"|"corrupt"|"unavailable"|"timeout"|"error",
               retries=0, error=None, injected=False)
DeleteResult(deleted: list[str], failed: list[ProviderFailure])
AnchorWriteResult(key, stored_on, failed); AnchorRead(provider, outcome, data=None, error=None)
AnchorListing(keys: dict[str, list[str]], errors: dict[str, str])
# errors (all StorageError subclasses, retryable=False):
ChunkStoreError(.chunk_id, .failures: list[ProviderFailure], .cleanup_failed: list[str])
ChunkUnavailableError(.chunk_id, .attempts, .outcomes, .all_corrupt, .any_corrupt, .all_missing)
WriteVerificationError; CircuitOpenError (a ProviderUnavailable that is not retried); FaultInjectionDisabled;
InvalidObjectKey (also a ValueError); StorageConfigError
```

Semantics an integrator relies on:
- **Chunk keys and anchors.** The object key is the `chunk_id` itself. It must pass key validation and
  must not start with the reserved `anchors/` prefix. Anchor keys are always stored under `anchors/`;
  `put_anchor("cp-1")` and `put_anchor("anchors/cp-1")` are the same object.
- **`store_chunk` input check.** It first checks that `sha256_hex` equals SHA-256(`data`).
- **`store_chunk` writes and failover.** It writes to the R preferred targets in parallel. Each write
  goes through breaker check, deadline and retry. A target that fails is replaced by the next fallback
  candidate; fallbacks are sorted healthy-first. This continues until R replicas are stored or no
  candidates are left.
- **`store_chunk` verification.** A write counts only after verification:
  - `stat` must show the same size.
  - With `verify_writes=True` (the default), the object is also read back and its SHA-256 compared.
  - **Cost:** one extra GET of the whole chunk per replica, about doubling upload traffic. Without the
    read-back, a provider that returns same-size wrong bytes would be accepted at upload time. It would
    only be caught at download time by the caller's verify callback.
- **`store_chunk` results and errors.**
  - **Fewer than `min_write_replicas` verified replicas:** every provider that may hold a copy gets a
    best-effort delete, then `ChunkStoreError` is raised.
  - **`degraded`:** `len(stored_on) < replication_factor`.
  - **`failed_over`:** a fallback provider holds a replica.
- **`store_chunk` audit.** Audit `chunk.distribute` (`action="storage:write"`, `resource_type="chunk"`,
  `resource_id=chunk_id`) with details `{chunk_index, providers, attempts, failed_providers}`. Outcome is
  success (severity warning if anything failed) or error. If the audit sink raises on the success path,
  the stored replicas are deleted and the exception propagates.
- **`fetch_chunk` order.** Replicas are tried in this order: healthy and closed first, then
  unknown/unhealthy, then breaker-open last. Open providers are still tried as a last resort for reads.
  Retryable errors are retried.
- **`fetch_chunk` verification.** If `verify(data)` is False the replica is treated as `corrupt` and
  the next one is tried. If `verify` itself raises, the replica is recorded as `error`.
- **`fetch_chunk` audit.**
  - Per bad replica: `storage.replica.corrupt` (CRITICAL, outcome failure) or `storage.replica.missing`
    (WARNING, outcome failure), with details `{provider}`.
  - Overall: `chunk.retrieve` (`action="storage:read"`) with details
    `{providers, attempts, failed_providers, outcomes}`. On failure the outcome is `failure`+CRITICAL
    when every replica was corrupt, otherwise `error`.
  - No valid replica: raise `ChunkUnavailableError`.
  - Audit sink exceptions propagate (data is not returned).
- **`delete_chunk`.** It never raises for provider errors or missing objects; failures are reported in
  `DeleteResult.failed`.
- **`repair_chunk`.** It refuses data whose hash does not match. It rewrites bad/missing providers first,
  then other providers in placement order. It deletes corrupt copies it could not replace (best effort)
  and audits `chunk.repair`. It returns the new replica list, which may be shorter than R. The caller
  must re-seal the manifest (ADR-0003).
- **Anchors.** Anchor writes go to **all** providers, best effort, verified by size. They are **not
  audited** by the orchestrator, because the audit subsystem calls it while checkpointing and auditing
  from inside would recurse.
- **Passive health.**
  - Every provider operation's final outcome is reported to the `HealthMonitor`.
  - Counted as failures: `ObjectNotFound` (the provider answered), `InvalidObjectKey` and an
    open-circuit skip are *not* failures; everything else is.
  - Write-verification failures are recorded as failures.
- **Audit detail keys for the audit privacy allow-list.** `chunk_index, providers, attempts,
  failed_providers, outcomes, provider, healthy, state, previous_state, consecutive_failures, injected`.
  Event types: `chunk.distribute`, `chunk.retrieve`, `chunk.repair`, `storage.replica.corrupt`,
  `storage.replica.missing`, `storage.provider.health`.
- **Request context on storage events (finding F5).** The orchestrator's signatures carry no request
  context. Instead the API opens an ambient `app.audit.context` contextvar per request (request id, client
  IP, and the actor bound by `get_caller`), and `AuditService.record` fills those fields when an emitter
  leaves them `None`. The orchestrator's fan-out pool and `DeadlineRunner` submit work with
  `contextvars.copy_context().run`, so `chunk.distribute`, `chunk.retrieve`, `chunk.repair`,
  `storage.replica.corrupt/missing` (and a `storage.provider.health` transition observed during a request)
  carry the triggering request's id, actor pseudonym and source network. The background health monitor and
  maintenance thread run outside any request and stay unattributed.
- **Thread safety.** All mutable state lives in `StorageMetrics` / `HealthMonitor` (locked), so any
  method can be called from concurrent request threads. This is tested with 32 threads, 64 store+fetch
  pairs and a provider in `fail-n`.

## Configuring real cloud providers

Set `ZT_STORAGE_PROVIDERS=aws-s3,azure-blob,gcs` and leave every `*_ENDPOINT_URL` **unset**.

- **AWS S3:**
  - Set `ZT_S3_BUCKET` and `ZT_S3_REGION`.
  - Prefer the default credential chain: an instance/task role, `AWS_PROFILE`, or SSO. Only if
    unavoidable, set `ZT_S3_ACCESS_KEY_ID` + `ZT_S3_SECRET_ACCESS_KEY` (both or neither).
  - Least-privilege IAM policy for the app identity, on one bucket only:
    `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject` on `arn:aws:s3:::<bucket>/*` and `s3:ListBucket`
    on `arn:aws:s3:::<bucket>`. HEAD bucket, used by `health()`, is authorised by `s3:ListBucket`.
  - Do **not** grant `s3:CreateBucket`, `s3:PutBucketPolicy`, `s3:*Acl*`, lifecycle or KMS key-admin
    permissions; create the bucket out of band.
  - If the bucket uses SSE-KMS, the role additionally needs `kms:GenerateDataKey`/`kms:Decrypt` on that
    key only. This is separate from the app's own envelope encryption.
  - Enable Block Public Access.
- **Azure Blob:**
  - Set `ZT_AZURE_CONNECTION_STRING` (inject from a secret store, never commit it) and `ZT_AZURE_CONTAINER`.
  - Prefer a connection string carrying a **container-scoped SAS** with permissions `r,c,w,d,l` and an
    expiry over an account key. An account key grants full control of the whole storage account.
  - The `get_container_properties` health probe works with a container SAS that has read permission.
  - Managed-identity (Entra ID) auth is **not implemented** in this adapter (see limitations). It would
    need the "Storage Blob Data Contributor" role scoped to the one container.
- **GCS:**
  - Set `ZT_GCS_BUCKET` and `ZT_GCS_PROJECT`. Credentials come from Application Default Credentials:
    workload identity, an attached service account, or `GOOGLE_APPLICATION_CREDENTIALS` pointing to a
    key file kept out of the repo.
  - Grant the service account `roles/storage.objectUser` (object get/create/delete/list) **on the
    bucket only**, plus `storage.buckets.get` for the health probe (e.g. a custom role, or
    `roles/storage.legacyBucketReader` on the bucket).
  - Do not grant `roles/storage.admin` or project-level storage roles.
- **No key permissions anywhere.** No identity used by this layer needs access to the application's
  KMS keys: providers only ever receive ciphertext.

## Local emulators

```
scripts/emulators.sh start | stop | status | reset | start-one <s3|azure|gcs> | stop-one <s3|azure|gcs>
source scripts/.emulators/run/emulators.env      # ZT_* variables for the backend
```
| Emulator | Port | Data | Version used |
|---|---|---|---|
| moto server (`backend/.venv/bin/moto_server -H 127.0.0.1 -p 5001`) | 5001 | in memory (lost on stop) | moto 5.2.5 |
| Azurite blob (`scripts/.emulators/node_modules/.bin/azurite-blob --blobHost 127.0.0.1 --blobPort 10000 --location scripts/.emulators/data/azurite --skipApiVersionCheck --disableTelemetry --silent`) | 10000 | on disk | Azurite 3.37.0 |
| gcp-storage-emulator (`backend/.venv/bin/gcp-storage-emulator --data-dir scripts/.emulators/data/gcs start --host 127.0.0.1 --port 9023`) | 9023 | on disk | 2026.7.19 |

- **Processes and files.** The emulators run as background processes (via `setsid`). Pid files and
  logs are in `scripts/.emulators/run/`. `stop` kills only pids it recorded, and only if the process
  command line still matches the emulator.
- **Buckets.** Buckets/containers are created by `scripts/emulators/ensure_buckets.py`, which uses the
  adapters' `ensure_bucket()`. The helper refuses to run against anything that is not an emulator endpoint.
- **Credentials.** S3 uses dummy credentials `test`/`test`. Azure uses Microsoft's **public, documented**
  `devstoreaccount1` development key, which is not a secret.
- **Restarting S3.** `stop-one s3` loses all moto data, because moto is in-memory. `start-one s3`
  recreates the empty bucket.

## Tests

```
cd backend && .venv/bin/python -m pytest tests/unit/storage tests/integration/storage -q -rs
```
- `tests/unit/storage/` (no network except connection-refused checks against `127.0.0.1:1`) contains:
  - the shared contract suite (`contract_suite.py`), run on `MemoryProvider` and a pass-through
    `FaultInjectingProvider`;
  - tests for retry/backoff/jitter/deadline, placement, fault modes, metrics, and health/circuit breaker
    (with an injected clock);
  - orchestrator tests: failover, degraded, all-down cleanup, fail-n retry, timeout, deadline, lying
    providers, corrupt/missing replicas, delete, repair, anchors, 32-thread concurrency, no payload in
    audit events;
  - factory tests, sanitisation tests, and adapter error translation.
- `tests/integration/storage/` (`@pytest.mark.emulator`) contains:
  - the same contract suite against `S3Provider`→moto, `AzureBlobProvider`→Azurite and
    `GCSProvider`→gcp-storage-emulator;
  - an orchestrator test with 10 chunks at R=2. Physical spread is checked through each SDK adapter's
    `list_keys` (6/7/7 split), then every chunk is fetched back and deleted;
  - anchors on all three emulators;
  - a **real outage test**: it kills the GCS emulator with `scripts/emulators.sh stop-one gcs`, checks
    that the health probe reports it down (not injected), that reads fail over, and that new writes
    avoid it, then restarts it and checks recovery and data persistence.
- **Skipping.** Each emulator fixture **skips with a reason** when its endpoint is not reachable; it
  never passes silently.

Last run (2026-11-12, emulators running):
```
tests/unit/storage                         145 passed in 1.87s
tests/integration/storage                   78 passed in 6.36s
tests/unit/storage tests/integration/storage  223 passed in 9.00s   (0 failed, 0 skipped; repeated 5x, all green)
```
With the emulators stopped (verified after the run above), every integration test is skipped with a
reason, e.g. `SKIPPED [1] ...: moto S3 emulator not reachable at http://127.0.0.1:5001 (run
scripts/emulators.sh start)`. The result was `78 skipped`.

## Limitations / not implemented

- **Emulators only.** Nothing has been run against real AWS, Azure or GCP (see top of this file).
- **No streaming or multipart uploads.** Objects are put and read whole in memory, which suits the
  1 MiB chunks. Very large objects would need multipart / resumable uploads; this is not implemented.
- **Azure auth.** Only connection strings (account key or SAS) are supported. Managed identity /
  `DefaultAzureCredential` is not implemented.
- **Thread-based deadlines.** The deadline guard cannot cancel a hung SDK call. After a deadline-timed-out
  put, the cleanup delete can race the late write and leave an orphan object (ciphertext only, not
  referenced by any manifest). There is no orphan garbage collector.
- **Single-process health state.** The circuit breaker and health state are in-process; nothing is
  shared between backend instances.
- **Anchor verification.** Anchors are verified by size only (no read-back hash). The audit module
  verifies anchor signatures itself.
- **Health in multi-tenant setups.** Health probes check bucket reachability and permissions on the
  bucket, not per-object permissions.
- **Placement assumptions.** `RotatingPlacement` assumes a stable provider order (the order of
  `ZT_STORAGE_PROVIDERS`). Changing that order changes where *new* chunks go. Existing chunks are found
  through the manifest's replica list, so nothing breaks.
- **Unit tests.** `MemoryProvider` exists for unit tests only and is refused outside `env=test`.
