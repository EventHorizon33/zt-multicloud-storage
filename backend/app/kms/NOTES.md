# app/kms — NOTES

Phase 3. Depends only on `app.contracts`, `app.errors` (and `app.config` duck-typed via `build_kms`).

## Public API

```python
from app.kms import build_kms, LocalKMS, AwsKMS, load_root_key

build_kms(settings) -> KeyManagementService          # settings.kms_backend: "local" | "aws"
load_root_key(settings) -> bytes                     # 32-byte keystore root key

LocalKMS(keystore_path: str | PathLike, root_key: bytes, *, clock: Callable[[], datetime] | None = None)
    # all KeyManagementService methods, plus:
    .ensure_keys() -> list[KeyInfo]                  # create v1 of every purpose that has none

AwsKMS(key_id: str, local: KeyManagementService, *, client=None, endpoint_url: str | None = None,
       region_name: str | None = None, version_cache_ttl: float = 60.0, monotonic=time.monotonic)
```

Every method of `contracts.KeyManagementService` is implemented by both classes
(`generate_data_key`, `unwrap_data_key`, `rewrap_data_key`, `wrapped_key_version`,
`encrypt`, `decrypt`, `sign`, `verify`, `public_key_pem`, `mac`, `rotate`, `list_keys`).
All failures raise `app.errors.KmsError`; `verify` returns `False` instead of raising.

## LocalKMS

* **Root key**: 32 bytes, constructor argument. `load_root_key` order:
  `ZT_KMS_ROOT_KEY` (base64) → `ZT_KMS_ROOT_KEY_FILE` (file with base64) → in env
  `test`/`development` only, generate once into `<data_dir>/kms/dev-root.key` (0600,
  `O_EXCL`) and log a WARNING; in any other env (production) raise `KmsError`.
  The dev key sits next to the keystore, so it protects nothing against someone who
  can read that directory. That is why it is dev-only.
* **Root key use**: HKDF-SHA256 derives two keys from it, an entry-encryption key
  (AES-256-GCM) and a keystore MAC key (HMAC-SHA256).
* **Keystore file** (`settings.kms_keystore_path`, default `<data_dir>/kms/keystore.json`),
  JSON, mode 0600, written atomically (temp file `O_EXCL` 0600 → write → fsync →
  `os.replace` → fsync dir):
  ```json
  {"format":"zt-kms-keystore","v":1,
   "keys":{"<purpose>":{"key_id":"local/<purpose>",
                         "versions":[{"v":1,"alg":"AES-256-GCM","created_at":"<iso>",
                                      "nonce":"<b64>","ct":"<b64 AES-GCM(material)>"}]}},
   "mac":"<hex HMAC-SHA256 over canonical JSON of format,v,keys>"}
  ```
  Entry AAD = `"zt-kms-keystore-entry-v1" | lp(purpose) | lp(key_id) | u32 version | lp(alg) | lp(created_at)`
  (`lp` = u32 big-endian length prefix). Swapping entries between purposes/versions fails
  entry authentication even if the file MAC were recomputed. The file MAC also catches
  removal of a whole version or purpose, which per-entry AEAD alone cannot catch.
* **Purposes**: FILE_DEK_WRAP, SECRET_ENCRYPTION → AES-256-GCM; TOKEN_SIGNING,
  AUDIT_SIGNING → Ed25519 (raw 32-byte private seed stored); AUDIT_PSEUDONYM,
  LOOKUP_HMAC → 32-byte HMAC-SHA256 keys. Each purpose has independent random
  material. Keys are created lazily on first use or by `ensure_keys()`.
  Key ids are `local/<purpose value>`.
* **Versions**: `rotate(purpose)` appends version n+1, which becomes active. Older
  versions are `decrypt-only`. They are used only for unwrap/decrypt/verify/`public_key_pem(version=)`.
  wrap/encrypt/sign/mac always use the newest version. Nothing is ever `retired`
  (no deletion of old versions is implemented).
* **Concurrency**: `threading.RLock` in-process. Keystore read-modify-write also takes an
  advisory `fcntl.flock` on `<keystore>.lock` (POSIX), and an instance reloads the file
  when its stat signature (mtime_ns, size, inode) changes. So two processes sharing a
  keystore see each other's rotations. If the keystore file disappears after load, the
  instance raises instead of silently recreating keys.
* **Wrapped-blob format** (data keys and secrets):
  ```
  "ZTK1" | u8 kind (0x01 data key, 0x02 secret) | u8 len(key_id) | key_id ascii | u32 version
         | nonce(12) | AES-256-GCM ciphertext || tag(16)
  AAD = "zt-kms-blob-aad-v1" | lp(header bytes "ZTK1".."version") | canonical(context)
  canonical(context) = u32 count | for keys sorted: lp(key utf-8) | lp(value utf-8)
  ```
  Context must be a `Mapping[str, str]` (≤32 entries, non-empty keys, ≤1024 bytes each).
  A different context, any modified byte, a truncated blob, a blob of the other kind,
  or an unknown version raises `KmsError`. `wrapped_key_version` reads only the header
  (unauthenticated, so use it only to plan rotation).
* `encrypt`/`decrypt`: secrets up to 64 KiB under SECRET_ENCRYPTION, same blob format with kind 0x02.
* `rewrap_data_key` → `DataKey(plaintext=b"", ...)` under the active version.
* `__repr__` shows only the path. Key material is never logged; log lines contain only
  purpose names and version numbers.

## AwsKMS. Scope stated plainly

**Only envelope operations go to AWS KMS**: `generate_data_key` (`GenerateDataKey`,
`KeySpec="AES_256"`), `unwrap_data_key` (`Decrypt` with `KeyId` pinned), `rewrap_data_key`
(`ReEncrypt`, so the data key never enters this process), `encrypt`/`decrypt` for small
secrets (`Encrypt`/`Decrypt`, ≤4096 bytes), and `rotate(FILE_DEK_WRAP)`
(`RotateKeyOnDemand`). All of these use one symmetric customer-managed key (`ZT_AWS_KMS_KEY_ID`).

**Signing and MAC purposes are delegated to the injected `LocalKMS`**: `sign`, `verify`,
`public_key_pem`, `mac`, `rotate(<signing/HMAC purpose>)`. Reasons: (1) these keys are
used on every request (token verification, refresh-token lookup, audit pseudonyms), and
an AWS round-trip each time would add latency and cost; (2) the contract needs
versioned keys where old versions stay verifiable after rotation, and AWS asymmetric
and HMAC keys do not support automatic/on-demand rotation, so emulating versions would
need one AWS key per version plus our own bookkeeping, which was out of scope for this
phase (AWS signing/HMAC under moto was not attempted). In `aws` mode the
signing/MAC keys therefore still live in the local encrypted keystore under the local root key.

Details:
* Wrapped blob: `"ZTA1" | u8 kind | u16 len(arn) | key ARN | u32 version label | AWS CiphertextBlob`.
* The AWS `EncryptionContext` = caller context + `zt_kms_use` (`data-key`/`secret`) +
  `zt_kms_version` (version label). Callers may not use those two key names.
  Modifying the header's kind or version therefore makes AWS reject decryption.
  AWS logs encryption contexts in CloudTrail in clear text, so contexts must hold only
  non-secret ids (file_id/owner_id are fine).
* "Version" = 1 + number of entries in `ListKeyRotations` (cached 60 s). AWS key
  material versions are internal to AWS, so this is a label for planning rewraps.
  AWS decrypts old ciphertext with whichever material produced it.
* `rotate(SECRET_ENCRYPTION)` raises `KmsError`, because it shares the AWS key with
  FILE_DEK_WRAP. If the installed boto3 lacks `rotate_key_on_demand`, `rotate` enables
  automatic rotation and raises `KmsError` saying no new version exists yet.
* `list_keys` reports the AWS key once per AWS-backed purpose (current version label
  only, state `active`) plus the delegate's signing/MAC keys.
* Every botocore error becomes `KmsError("AWS KMS <Operation> failed: <ErrorCode>")`,
  with no parameters, context values or ciphertext in the message.

**Testing caveat:** `tests/unit/kms/test_kms_aws_moto.py` drives the real boto3 KMS client
against **moto's in-process mock** (`moto.mock_aws`, moto 5.2.5). Every call used here was
confirmed to work under moto (GenerateDataKey, Decrypt incl. wrong-context rejection,
ReEncrypt, Encrypt, DescribeKey, RotateKeyOnDemand, ListKeyRotations). **This is NOT a
test against real AWS KMS.** IAM policies, real rotation timing (on-demand rotation is
asynchronous on AWS; the code takes `max(listed, before+1)` to cover that), throttling
and CloudTrail behaviour have not been verified.

## Not implemented

* Retiring or deleting old key versions (state `retired` is never produced).
* Re-encrypting SECRET_ENCRYPTION blobs after rotation. There is no `rewrap` for secrets in
  the contract; callers can `decrypt` + `encrypt`.
* Root-key rotation for the local keystore (would need a re-encryption tool).
* HSM / PKCS#11 backends; AWS KMS for signing/HMAC (see above).
* Python cannot guarantee that key material is wiped from memory.

## Tests

```
cd backend && .venv/bin/python -m pytest tests/unit/kms -q
```
Last run: **73 passed** (`test_kms_local.py`, `test_kms_aws_moto.py`), see the combined run below.

Combined run of both Phase 3 suites (last run):
```
cd backend && .venv/bin/python -m pytest tests/unit/kms tests/unit/cryptoengine -q
176 passed
```
