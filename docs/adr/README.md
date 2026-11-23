# Architecture Decision Records

## ADR-0001: Envelope encryption with a per-file data key and HKDF key separation

**Status:** accepted

**Context.** Chunks must be encrypted before leaving the backend, keys must not sit next to ciphertext, and encryption and authentication keys must be separate.

**Decision.**
- Each file gets a random 256-bit data key (DEK) from the KMS. The DEK is wrapped with AES-256-GCM under a versioned key-encryption key (KEK); the wrap is bound (AAD) to `{file_id, owner_id}`.
- From the DEK, HKDF-SHA256 derives three independent keys with distinct `info` labels: `chunk-encryption`, `manifest-mac`, `metadata-encryption`.
- Only the wrapped DEK is stored (metadata DB). Providers receive no key material.

**Consequences.** Rotating a KEK only re-wraps DEKs (no chunk re-encryption). Deleting the wrapped DEK crypto-shreds a file even if provider deletes fail. Moving a wrapped key to another file row, or changing a file's owner in the DB, makes unwrap fail.

**Rejected.** One global data key (single point of failure, no shredding); per-chunk random keys stored in the manifest (larger manifest, no added security over AAD binding).

## ADR-0002: Chunk AEAD construction

**Status:** accepted

**Decision.** Each chunk is `nonce(12) || AES-256-GCM(ciphertext || tag)` with a fresh random nonce and AAD = `format_version | file_id | chunk_index | final_flag`. The final flag marks the last chunk (a STREAM-style construction), so the engine can encrypt a stream without knowing the chunk count in advance while still detecting truncation. An empty file is one final chunk with empty plaintext.

**Consequences.** A chunk cannot be moved to another position or file, and the last chunk cannot be dropped, without failing authentication. Random 96-bit nonces under a per-file key are safe far beyond any realistic chunk count per file (bound: 2^32 chunks per key; enforced limit is far lower).

Independently of the GCM tag, the SHA-256 of each stored blob is recorded in the manifest. This lets the orchestrator reject a bad replica and fail over **without** holding any key.

## ADR-0003: Manifest as MAC-protected source of truth

**Status:** accepted

**Decision.** The manifest is canonical JSON (sorted keys, no whitespace) containing file ID, owner ID, sizes, chunk size, ordered chunk list (object ID, ciphertext size, SHA-256), replica locations, classification, plaintext SHA-256, and the hash of the encrypted metadata blob. It is authenticated with HMAC-SHA256 under the DEK-derived `manifest-mac` key. The `chunks` / `chunk_replicas` tables are a convenience projection for the UI and are never trusted during reconstruction.

**Consequences.** Changing chunk order, location, count, or hashes in the database is detected before any chunk is fetched. Repair (re-replication) must re-seal the manifest, which needs the DEK, so repair is an authorised, audited operation.

## ADR-0004: Replication, not erasure coding

**Status:** accepted

**Decision.** Each chunk is written to `replication_factor` distinct providers (default 2 of 3) chosen by a placement strategy that rotates the starting provider per chunk. An upload commits only if every chunk reached `min_write_replicas`; if a target is down the orchestrator fails over to another healthy provider before giving up.

**Consequences.** Any single provider outage is survivable for reads. No provider holds every chunk of a multi-chunk file's replica set alone unless R equals the provider count. Storage overhead is R×. The system never claims to reconstruct data when all replicas of a chunk are gone; it reports `data-unavailable`.

**Trade-off stated plainly.** With R=2 of 3, each provider holds about two-thirds of the ciphertext chunks. Setting R=1 gives the strongest dispersal (each provider holds a third) and no fault tolerance. This is configuration, and the documentation states which mode a demo is running in.

**Rejected.** Reed-Solomon erasure coding: better storage efficiency, but more code to get wrong, and not needed to demonstrate the security properties.

## ADR-0005: Verify-then-release on download

**Status:** accepted

**Decision.** A download is fully fetched, verified (per-chunk hash, AEAD tag, whole-file SHA-256, size) and only then streamed to the client.

**Consequences.** Corrupted content is never partially delivered. Cost: latency to first byte and server-side buffering (spooled to an unlinked temp file above a threshold; the temp file holds plaintext briefly on the backend host, which is inside the trust boundary).

## ADR-0006: Audit integrity: hash chain, signed checkpoints, external anchors, separate store

**Status:** accepted

**Decision.**
- Every audit record stores `hash = SHA-256(prev_hash || canonical(record))`, with a strictly increasing sequence number.
- Every N records (and on demand) an Ed25519-signed checkpoint `{seq, head_hash, timestamp}` is written, and the checkpoint is also uploaded to the storage providers as an anchor.
- The audit log uses its own database, separate from metadata.
- Appends are serialised (process lock; Postgres advisory lock when on Postgres).
- Retention deletes only whole prefixes that end at a signed checkpoint; that checkpoint becomes the verifiable starting point.

**Consequences.** Modification, deletion in the middle, and reordering break the chain. Truncation of the tail is caught by comparing against the latest checkpoint and its anchors. A blockchain would add distributed consensus that nothing here requires.

**Limit.** Records newer than the last anchored checkpoint can be truncated undetected until the next checkpoint.

**Amendment (Phase 8 fix, finding F4): anchors are namespaced per audit log.**
*Context.* Anchor keys were `anchors/audit/checkpoint-<seq>.json`, identical for every deployment. Two deployments sharing a bucket (staging and production, a reinstall with a new keystore, test runs, the demo) overwrote each other's anchors at equal sequence numbers: the overwritten log lost its external evidence and its verification reported `anchor-mismatch` (`ok=false`) although nobody had tampered. This was observed three times during security testing.
*Decision.* Keys are `anchors/audit/<log_id>/checkpoint-<seq:012d>.json` and `anchors/audit/<log_id>/retention-<seq:012d>.json`, with `log_id = sha256(SubjectPublicKeyInfo PEM of audit-signing key version 1)[:16 hex]`. Verification lists and trusts only its own namespace; anchors of other logs and legacy un-namespaced anchors are ignored. The identifier is derived from the KMS rather than stored in the audit DB, so it survives signing-key rotation and cannot be changed by wiping or replacing the audit DB (old anchors keep exposing a truncation). Emulator tests and the demo additionally use private per-run buckets.
*Consequences.* Sharing a bucket between deployments is safe for audit verification. After an upgrade, checkpoints anchored under the legacy keys report the informational `anchor-missing`. A deployment moved to a different audit-signing keystore writes to a new namespace; its predecessor's anchors remain verifiable with the old public key but are not consulted automatically.

## ADR-0007: Privacy in the audit log

**Status:** accepted

**Decision.** Actors are stored as `HMAC-SHA256(pseudonym_key, user_id)` truncated to 16 hex-encoded bytes. Event details pass through an allow-list of field names per event type; anything else is dropped and counted. Source IPs are generalised to /24 (IPv4) or /48 (IPv6). Filenames, usernames, tokens, keys and content never enter the log. Users can see their own events; auditors and admins see all events with pseudonyms. Mapping a pseudonym back to a user requires an explicit, audited admin lookup.

**Consequences.** Investigators can correlate all actions of one actor without learning who it is until re-identification is justified. ~~Rotating the pseudonym key breaks linkability across the rotation, which is a deliberate privacy lever.~~ (superseded by the amendment below)

**Amendment (independent review, findings M1 and M3): the lookup really is the only mapping, and the pseudonym key is not rotatable through the API.**
*Context.* The decision above promised that mapping a pseudonym to a user needs an explicit, audited admin lookup. In fact `GET /api/admin/users` (granted to auditors through `user:list`, no MFA) returned `username` + `audit_pseudonym` for every account: a complete reverse table, without any `audit.reidentify` record (M1). Separately, one administrator with fresh MFA could rotate the pseudonym key through `POST /api/admin/kms/rotate`; pseudonyms were only ever computed with the active version, so afterwards the audited lookup could not resolve any pre-rotation actor and every user's "own events" view lost its history. An administrator could act, rotate, and leave events nobody could tie to an account through the product (M3). The "privacy lever" was in practice an accountability-erasure lever held by a single person.
*Decision.*
1. The user view (`AdminService.user_view`) carries no pseudonym. The auditor role loses `user:list`: auditors work with pseudonyms only (audit trail, verification, key metadata). The only mapping path is `POST /api/admin/pseudonym-lookup` (`user:manage`, fresh admin MFA, always audited `audit.reidentify` with the target pseudonym). The UI shows auditors a key-metadata view without a directory.
2. `POST /api/admin/kms/rotate` with `purpose=audit-pseudonym` is refused with `403 pseudonym-key-rotation-disabled` and audited (`admin.kms.rotate`, outcome denied). Rotating the pseudonym key is an **offline, two-person operation**: two operators with access to the KMS keystore and root key (one runs it, one witnesses and records it out of band), with the server stopped, after an audit checkpoint has been anchored. Old key versions are never deleted.
3. Matching considers every retained key version: `AuditService.pseudonyms_for(user_id)` returns one pseudonym per version (`KeyManagementService.mac_all_versions`). The re-identification lookup, the "own events" scope (search, event by seq, export: `actor IN (...)`), the own security feed and the own dashboard counters use that set, so a rotation done out of band does not orphan anybody's history and does not make past actions unattributable.
*Consequences.* Linkability across a rotation is preserved for the product (lookup and own views); an investigator correlating raw records still sees two different pseudonyms for one person across a rotation, which is the remaining privacy effect of a rotation. Unlinking is no longer available as a one-person API action. Re-identification remains admin-only; an auditor who needs a name asks an admin, and the request leaves an `audit.reidentify` record. Tests: `tests/review/test_review_audit.py::test_fixed_auditor_cannot_reidentify_pseudonyms_through_the_user_list`, `::test_fixed_pseudonym_key_rotation_is_refused_and_history_survives_offline_rotation`.

## ADR-0008: Zero-trust enforcement model

**Status:** accepted

**Decision.** A pure Policy Decision Point evaluates `(subject, action, resource, context)` and returns allow/deny with reason codes. A Policy Enforcement Point wraps every sensitive API operation, loads the resource, calls the PDP, audits the decision, and raises on deny. Default is deny: an action with no matching allow rule is refused. Subject attributes (role, active flag, allow list, session state) are re-read from the database on every request, never taken from the token.

**Consequences.** Role changes, account disablement and session revocation take effect on the next request, not at token expiry. The cost is one indexed DB read per request.

## ADR-0009: Tokens

**Status:** accepted

**Decision.** Access tokens are EdDSA-signed JWTs (5-minute TTL) carrying only `sub`, `sid`, `jti`, `iat`, `exp`, `iss`, `aud`, `typ`. Refresh tokens are 256-bit opaque random values, delivered in an HttpOnly, SameSite=Strict cookie scoped to `/api/auth`, stored only as an HMAC, single-use and rotated. Presenting a used refresh token revokes the session.

**Consequences.** A stolen refresh token is detected at the next legitimate refresh. No authorisation data is trusted from the token.

## ADR-0010: MFA at sign-in, and who may establish the second factor (trust on first use)

**Status:** accepted (Phase 8 fix for finding F1; also makes `require_mfa_for_login` the default)

**Context.** UNC5537 used infostealer passwords against accounts without MFA. Security testing found that this system's own MFA enrolment could be turned against its owner: a session that had proved only the password could enrol a factor, and activation then (a) marked that session MFA-verified, unlocking confidential downloads, delete and share, and (b) revoked every other session and made the factor mandatory at login, locking the real owner out behind the attacker's authenticator. `require_mfa_for_login` did not help, because restricted sessions must be able to reach enrolment. The root problem: a password-only session cannot be told apart from a thief holding the password, so it must not be the thing that decides which factor proves identity from now on.

**Decision.**
1. **Activation grants nothing.** `activate_mfa` neither stamps the current session `mfa_verified_at` nor revokes other sessions. MFA-verified status comes only from a new login with the code or a step-up (`/api/auth/mfa/verify`). Activation is audited `auth.mfa_activate` at WARNING (reason `new-factor`, `details.method` = enrolment basis, source network).
2. **Who may enrol a first factor.** Without approval only (a) an account that never had a factor and is within `mfa_self_enroll_window_seconds` (default 24 h) of registration (*trust on first use*: the password is new, so the chance that it is already stolen is lowest), or (b) the configured bootstrap admin, regardless of the window, while no other active admin holds a factor (nobody exists who could approve it). Everyone else needs a **single-use, time-limited admin enrolment code**: `POST /api/admin/users/{id}/mfa-enrollment-code` (`user:manage` + admin MFA verified within the step-up window, enforced in code even if the runtime policy is loosened; not for one's own account; 80-bit code shown once, only a user-bound HMAC stored, 24 h, a new code revokes the previous one; audited WARNING). Without one: `403 mfa-enrollment-requires-approval`. Once an account has had a factor (`MfaFactorState.ever_enabled`) the window never reopens, also after disable or reset.
3. **Replacing a factor** needs a valid code from the current factor; the current factor keeps working until the new one is activated.
4. **Recovery.** `POST /api/admin/users/{id}/mfa-reset` (`user:manage` + fresh admin MFA) removes the factor, revokes all the user's sessions and is audited; the user then needs an enrolment code.
5. **MFA at sign-in by default.** `require_mfa_for_login` defaults to true: password-only sessions can only reach `/api/auth/*` (enrolment) and `security:read`/`policy:read`. Combined with 1, a thief with a password gets a session that can do nothing but (inside the window) enrol.
6. The network allow list (F2) applies to enrol/activate/verify/disable as well.

**Consequences.** A stolen password for an account older than the window, or one that has had MFA, cannot establish a factor, and the victim is never locked out by an attacker's factor. Users must sign in again after activating (one extra step; the UI says so). Accounts that miss the 24 h window need an administrator. A pending enrolment expires after `mfa_pending_enrollment_ttl_seconds` (15 min), so a consumed admin code can be wasted by a slow user.

**Residual risk (stated, and demonstrated by `test_s11_stated_limit_tofu_window`).** A password stolen *inside* the TOFU window before the owner enrols lets the thief enrol their own factor and then step up with it. This is detective (WARNING events with the thief's network) and recoverable (admin reset), not prevented. Until the bootstrap admin enrols, its password alone can establish the admin factor. Admin enrolment codes are a privileged path: a rogue or compromised admin (with their own fresh MFA) can let any non-admin account be enrolled by whoever receives the code; issuance and use are audited.

**Amendment (independent review, findings M5 and H1).** Item 5 claimed that a password-only session can reach only enrolment; in fact every `/api/auth/*` endpoint was open to it, including session list/revoke and password change, so a thief with the password could sign the owner out and change the password. Now a *restricted* session (no factor, or not MFA-verified while `require_mfa_for_login` applies) may use only `me`, `logout`, `refresh`, MFA enrol/activate (with the gating above) and `security:read`/`policy:read`; session list/revoke and password change answer `403 mfa-required`. Password change additionally needs a factor verified within the step-up window (`403 mfa-required`/`mfa-stale` + `step-up-mfa`), is refused for accounts without a factor, and never revokes a session that verified the factor more recently than the caller's (or any MFA-verified session when the caller's is not). Replacing a factor clears the MFA-verified status of every other session. Tests: `tests/review/test_review_auth.py::test_fixed_restricted_password_only_session_is_limited_to_mfa_enrolment`, `::test_fixed_password_change_needs_fresh_mfa_and_cannot_evict_the_mfa_owner`, `::test_fixed_password_change_never_revokes_a_more_recently_verified_session`, `::test_fixed_replacing_the_factor_clears_mfa_status_of_other_sessions`.

**Rejected.** Cooling-off period after activation (delays the attacker but still hands them the factor and locks the owner out afterwards); e-mail/SMS out-of-band confirmation (no such channel exists in this system); disabling self-enrolment entirely (every new user would need an admin, which a small deployment cannot staff).

## ADR-0011: Client IP behind proxies (X-Forwarded-For trust)

**Status:** accepted (independent review, finding H2)

**Context.** The client IP feeds the network allow list (PDP guard and the auth service, F2), rate-limit keys and the audit `source_net`. With `trust_forwarded_for=true` the middleware read only the **first** `X-Forwarded-For` header line and took its right-most entry. A proxy that appends its own header line instead of concatenating (HAProxy `option forwardfor`, several CDNs) leaves the client-supplied line first, so a client could choose its own IP: allow-list bypass, rate-limit evasion and a forged audit network. Malformed entries silently fell back to other addresses.

**Decision.**
1. `ZT_TRUST_FORWARDED_FOR=false` (default): the TCP peer is the client. Nothing in any header is trusted.
2. With trust on, **all** `X-Forwarded-For` header lines are joined in order (RFC 9110 §5.3: equivalent to one comma-separated line), split on commas, and the entry `ZT_TRUSTED_PROXY_HOPS` (default 1, range 1–16) positions **from the right** is the client: each trusted proxy appends exactly one entry, so everything left of that point is client-controlled and ignored.
3. Every entry must parse: IPv4, IPv6, `a.b.c.d:port`, `[v6]` or `[v6]:port` (port stripped, 1–65535). Anything else (names, `unknown`, zone ids, empty elements, bad ports), more than 64 entries or 4 KiB, or a chain shorter than the hop count → the request is refused with `400 bad-forwarded-for` instead of falling back to another address. A request without the header uses the TCP peer (it did not pass through an appending proxy).
4. `ZT_TRUSTED_PROXY_CIDRS` (optional): if set, the header is honoured only when the TCP peer is inside one of these networks; from any other peer it is ignored and the peer is the client.
5. The resolved IP is used everywhere: PDP context, auth allow-list checks, rate-limit keys (IPv4 address / IPv6 /64, finding L4), the ambient audit context (`source_net`).
6. No peer address is trusted for authorisation: `/metrics` needs a token (finding L5), because behind a same-host proxy every client is `127.0.0.1`.

**Consequences.** The operator must set the hop count to the number of proxies that append to the header; too low a value trusts a client-controlled entry, too high a value refuses requests with short chains (fail closed, visible as 400s). Proxies must be configured to append (not replace) the header, or to replace it with exactly the peer address and `hops=1`. `Forwarded` (RFC 7239) and `X-Real-IP` are not read. Tests: `tests/review/test_review_auth.py::test_fixed_xff_joins_all_header_lines_and_takes_the_trusted_hop`, `::test_fixed_malformed_xff_is_rejected_not_ignored`, `::test_fixed_xff_port_forms_are_parsed`, `::test_fixed_xff_hops_and_trusted_proxy_cidrs`, `::test_fixed_xff_resolved_ip_keys_the_rate_limit`.

**Rejected.** Left-most entry (client-controlled); "first public address" heuristics (spoofable); silently ignoring malformed entries (an attacker could steer which entry is chosen).
