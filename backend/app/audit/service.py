"""Audit service: append, pseudonymise, checkpoint, anchor, verify.

Security properties
-------------------
* Every event passes the privacy filter (``app.audit.privacy``) before it is
  hashed or stored; actors are stored only as keyed pseudonyms.
* Appends are serialised by a process lock **and** a database-level write
  lock (SQLite ``BEGIN IMMEDIATE`` / PostgreSQL ``pg_advisory_xact_lock``),
  and ``seq`` is the primary key, so two writers can never fork the chain.
* Each event is committed in its own transaction on the separate audit
  database, so it survives a rollback of the caller's business transaction.
  If the write fails, ``record()`` raises ``AuditWriteError``.
* Every ``audit_checkpoint_every`` events an Ed25519-signed checkpoint of the
  chain head is stored and (optionally) anchored on every storage provider.
* ``verify_chain`` recomputes every hash in streaming batches and checks
  links, sequence continuity, checkpoint signatures, checkpoint heads, anchor
  copies and the retention boundary, reporting every finding.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Iterator, Mapping, Protocol

from sqlalchemy import Connection, Engine, func, insert, select, update
from sqlalchemy.exc import IntegrityError as SAIntegrityError
from sqlalchemy.exc import SQLAlchemyError

from app.audit import privacy
from app.audit.chain import (
    CHECKPOINT_PAYLOAD_FIELDS, CHECKPOINT_VERSION, GENESIS_HASH, canonical_json,
    compute_hash, format_ts,
)
from app.audit.errors import AuditError, AuditWriteError
from app.audit.context import current_audit_context, current_client_request_id
from app.audit.models import CHECKPOINTS, EVENTS, begin_write
from app.audit.query import AuditQuery
from app.audit.records import (
    ANCHOR_PREFIX, CHECKPOINT_KINDS, INFORMATIONAL_FINDINGS, AuditContext, AuditRecord,
    Checkpoint, Finding, RetentionResult, VerificationReport, anchor_key, anchor_prefix,
)
from app.config import Settings
from app.contracts import KeyManagementService, KeyPurpose, Outcome, Severity

log = logging.getLogger(__name__)

PSEUDONYM_PREFIX = "u_"
PSEUDONYM_HEX_CHARS = 32            # 16 bytes of HMAC-SHA256 (ADR-0007)
MAX_APPEND_ATTEMPTS = 5
VERIFY_BATCH_SIZE = 1000
_ANCHOR_KEY_RE = re.compile(r"^anchors/audit/([0-9a-f]{16})/(checkpoint|retention)-(\d{12})\.json$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_LABEL_MAX = 64


class AnchorStore(Protocol):
    """What the audit service needs from the storage layer for anchors. Each
    method fans out to every configured provider and reports per provider."""

    def put_anchor(self, key: str, data: bytes) -> dict[str, bool]: ...
    def get_anchor(self, key: str) -> dict[str, bytes | None]: ...
    def list_anchors(self, prefix: str) -> dict[str, list[str]]: ...


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _enum_value(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


class AuditService:
    """Implements ``app.contracts.AuditSink`` plus checkpointing, verification,
    retention and query. Thread-safe; one instance per audit database per
    process."""

    def __init__(
        self,
        settings: Settings,
        kms: KeyManagementService,
        engine: Engine,
        *,
        anchor_store: AnchorStore | None = None,
        clock: Callable[[], datetime] | None = None,
        extra_allowed_details: Mapping[str, Any] | None = None,
    ):
        self.settings = settings
        self._kms = kms
        self._engine = engine
        self._anchor_store = anchor_store
        self._clock = clock or _utcnow
        self._extra_allowed = dict(extra_allowed_details or {})
        self._lock = threading.RLock()
        self._query = AuditQuery(engine)
        self.checkpoint_failures = 0     # periodic checkpoints that could not be created
        self.anchor_failures = 0         # anchor writes that raised
        self._last_checkpoint_seq = self._load_last_checkpoint_seq()
        self._log_id: str | None = None

    @property
    def engine(self) -> Engine:
        return self._engine

    def close(self) -> None:
        self._engine.dispose()

    @property
    def log_id(self) -> str:
        """Identifier of this audit log, used to namespace its anchors on the
        shared storage providers (ADR-0006 amendment, finding F4).

        ``log_id = sha256(SubjectPublicKeyInfo PEM of audit-signing key
        version 1)[:16 hex]``. Derived from the KMS, not stored in the audit DB:
        it is stable across signing-key rotation (version 1 stays the
        identity), differs between deployments with different keystores, and
        an attacker who wipes or replaces the audit DB cannot move the log to
        a fresh namespace, so the old anchors still expose the truncation.
        If version 1 cannot be read the lowest available version is used."""
        if self._log_id is None:
            try:
                pem = self._kms.public_key_pem(purpose=KeyPurpose.AUDIT_SIGNING, version=1)
            except Exception:
                versions = sorted(int(k.version) for k in self._kms.list_keys()
                                  if str(getattr(k, "purpose", "")) in (KeyPurpose.AUDIT_SIGNING.value,
                                                                         str(KeyPurpose.AUDIT_SIGNING)))
                pem = self._kms.public_key_pem(purpose=KeyPurpose.AUDIT_SIGNING,
                                               version=versions[0] if versions else None)
            self._log_id = hashlib.sha256(pem).hexdigest()[:16]
        return self._log_id

    # ================================================================== #
    # Pseudonyms
    # ================================================================== #
    def pseudonym_for(self, user_id: str) -> str:
        """Stable keyed pseudonym of a user id: ``"u_" + hex(HMAC)[:32]``.

        Same user -> same pseudonym (correlation); without the KMS key the
        pseudonym cannot be linked to a user id. There is deliberately no
        reverse table: re-identification means computing the pseudonym of a
        candidate user, which the caller must audit."""
        mac = self._kms.mac(str(user_id).encode("utf-8"), purpose=KeyPurpose.AUDIT_PSEUDONYM)
        return PSEUDONYM_PREFIX + mac.hex()[:PSEUDONYM_HEX_CHARS]

    def pseudonyms_for(self, user_id: str) -> set[str]:
        """Every pseudonym this user has had: one per retained version of the
        pseudonym key (finding M3). The API's "own events" scope and the
        audited re-identification match against this set, so a key rotation
        (which the API refuses, but an operator can do offline) does not
        orphan a user's history or make past actions unattributable. The
        active-version pseudonym is always included."""
        msg = str(user_id).encode("utf-8")
        macs = getattr(self._kms, "mac_all_versions", None)
        values = macs(msg, purpose=KeyPurpose.AUDIT_PSEUDONYM) if callable(macs) else []
        out = {PSEUDONYM_PREFIX + m.hex()[:PSEUDONYM_HEX_CHARS] for m in values}
        out.add(self.pseudonym_for(user_id))
        return out

    # ================================================================== #
    # Append
    # ================================================================== #
    def record(
        self,
        *,
        event_type: str,
        action: str,
        outcome: Outcome | str,
        actor_id: str | None = None,
        actor_role: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        reason: str | None = None,
        severity: Severity | str = Severity.INFO,
        details: Mapping[str, Any] | None = None,
        request_id: str | None = None,
        source_ip: str | None = None,
    ) -> AuditRecord:
        """Filter, pseudonymise, chain and durably store one event.

        Never raises because of *content* (sensitive content is redacted or
        dropped). Raises ``ValueError`` for an unknown outcome/severity or an
        empty event_type/action, and ``AuditWriteError`` if the event could
        not be committed: the caller must then abort the operation.

        ``request_id``, ``source_ip`` and the actor that the caller leaves as
        ``None`` are taken from the ambient request context, if any
        (``app.audit.context``, finding F5). The actor role is filled only
        together with an actor taken from the context."""
        ambient = current_audit_context()
        if ambient is not None:
            if request_id is None:
                request_id = ambient.request_id
            if source_ip is None:
                source_ip = ambient.source_ip
            if actor_id is None and ambient.actor_id:
                actor_id = ambient.actor_id
                if actor_role is None:
                    actor_role = ambient.actor_role
            client_rid = current_client_request_id()
            if client_rid and not (isinstance(details, Mapping) and "client_request_id" in details):
                # L8: the client's own X-Request-ID, kept apart from the
                # server-generated request_id column.
                details = {**(dict(details) if isinstance(details, Mapping) else {}),
                           "client_request_id": client_rid}
        outcome_v = _enum_value(outcome)
        severity_v = _enum_value(severity)
        if outcome_v not in {o.value for o in Outcome}:
            raise ValueError("unknown audit outcome")
        if severity_v not in {s.value for s in Severity}:
            raise ValueError("unknown audit severity")
        etype = privacy.scrub_text(event_type, max_length=_LABEL_MAX, check_blobs=False)
        act = privacy.scrub_text(action, max_length=_LABEL_MAX, check_blobs=False)
        if not etype or not act:
            raise ValueError("event_type and action are required")

        try:
            actor = self.pseudonym_for(actor_id) if actor_id else None
        except Exception:
            raise AuditWriteError("audit pseudonymisation failed") from None

        fields: dict[str, Any] = {
            "id": uuid.uuid4().hex,
            "event_type": etype,
            "action": act,
            "outcome": outcome_v,
            "severity": severity_v,
            "actor": actor,
            "actor_role": privacy.scrub_text(actor_role, max_length=32, check_blobs=False),
            "resource_type": privacy.scrub_text(resource_type, max_length=32, check_blobs=False),
            # resource ids are opaque random identifiers (often long hex), so the
            # blob heuristic is not applied; the JWT/PEM/email/bearer scan is.
            "resource_id": privacy.scrub_text(resource_id, max_length=128, check_blobs=False),
            "reason": privacy.scrub_text(reason, max_length=privacy.MAX_REASON_LENGTH),
            "details": canonical_json(privacy.filter_details(
                details, etype, extra_allowed=self._extra_allowed)),
            "request_id": privacy.scrub_text(request_id, max_length=64, check_blobs=False),
            "source_net": privacy.generalise_ip(
                source_ip, self.settings.audit_ip_prefix_v4, self.settings.audit_ip_prefix_v6),
        }

        with self._lock:
            row = self._append(fields)
            pending_anchor: Checkpoint | None = None
            every = self.settings.audit_checkpoint_every
            if every > 0 and row["seq"] - self._last_checkpoint_seq >= every:
                try:
                    pending_anchor = self._store_checkpoint(row["seq"], row["hash"], "periodic")
                except Exception:
                    # The event IS committed; failing record() now would make the
                    # caller believe it was not. The next append retries.
                    self.checkpoint_failures += 1
                    log.warning("audit periodic checkpoint failed at seq %s", row["seq"])
        if pending_anchor is not None:
            self._anchor(pending_anchor)
        return AuditRecord(seq=row["seq"], id=row["id"], ts=row["ts"], hash=row["hash"],
                           prev_hash=row["prev_hash"])

    def _head(self, conn: Connection) -> tuple[int, str]:
        """Current chain head (seq, hash). With no events: the latest
        retention checkpoint (everything pruned), else genesis (0, zeros)."""
        row = conn.execute(select(EVENTS.c.seq, EVENTS.c.hash)
                           .order_by(EVENTS.c.seq.desc()).limit(1)).first()
        if row is not None:
            return int(row[0]), row[1]
        cp = conn.execute(select(CHECKPOINTS.c.seq, CHECKPOINTS.c.head_hash)
                          .where(CHECKPOINTS.c.kind == "retention")
                          .order_by(CHECKPOINTS.c.seq.desc()).limit(1)).first()
        if cp is not None:
            return int(cp[0]), cp[1]
        return 0, GENESIS_HASH

    def _append(self, fields: dict[str, Any]) -> dict[str, Any]:
        for _ in range(MAX_APPEND_ATTEMPTS):
            try:
                with self._engine.connect() as conn:
                    try:
                        begin_write(conn)
                        head_seq, head_hash = self._head(conn)
                        row = dict(fields)
                        row["seq"] = head_seq + 1
                        row["ts"] = format_ts(self._clock())
                        row["prev_hash"] = head_hash
                        row["hash"] = compute_hash(row)
                        conn.execute(insert(EVENTS).values(**row))
                        conn.commit()
                        return row
                    except BaseException:
                        conn.rollback()
                        raise
            except SAIntegrityError:      # seq collision with another writer: retry
                continue
            except SQLAlchemyError:
                # no chaining: the DBAPI error can carry the statement parameters
                raise AuditWriteError("audit event could not be written") from None
        raise AuditWriteError("audit event could not be written (contention)") from None

    # ================================================================== #
    # Checkpoints and anchors
    # ================================================================== #
    def _load_last_checkpoint_seq(self) -> int:
        try:
            with self._engine.connect() as conn:
                v = conn.execute(select(func.max(CHECKPOINTS.c.seq))).scalar()
        except SQLAlchemyError:
            return 0
        return int(v or 0)

    def _sign_checkpoint(self, seq: int, head_hash: str, kind: str, first_seq: int,
                         ts: str) -> Checkpoint:
        unsigned = Checkpoint(id=uuid.uuid4().hex, seq=seq, head_hash=head_hash, ts=ts,
                              kind=kind, key_id="", key_version=0, signature="",
                              event_count=seq - first_seq + 1, first_seq=first_seq)
        sig = self._kms.sign(unsigned.payload().encode("ascii"), purpose=KeyPurpose.AUDIT_SIGNING)
        return Checkpoint(id=unsigned.id, seq=seq, head_hash=head_hash, ts=ts, kind=kind,
                          key_id=sig.key_id, key_version=int(sig.version),
                          signature=sig.signature.hex(), event_count=unsigned.event_count,
                          first_seq=first_seq, anchors={})

    def _first_seq(self, conn: Connection, default: int) -> int:
        v = conn.execute(select(func.min(EVENTS.c.seq))).scalar()
        return int(v) if v is not None else default

    def _store_checkpoint(self, seq: int, head_hash: str, kind: str,
                          conn: Connection | None = None) -> Checkpoint:
        """Sign and insert a checkpoint at (seq, head_hash). Caller holds the
        process lock. Uses ``conn`` (an open write transaction) if given,
        otherwise its own committed transaction."""
        if kind not in CHECKPOINT_KINDS:
            raise ValueError("unknown checkpoint kind")

        def _do(c: Connection) -> Checkpoint:
            cp = self._sign_checkpoint(seq, head_hash, kind, self._first_seq(c, seq),
                                       format_ts(self._clock()))
            values = cp.to_dict()
            values["anchors"] = "{}"
            c.execute(insert(CHECKPOINTS).values(**values))
            return cp

        if conn is not None:
            cp = _do(conn)
        else:
            with self._engine.connect() as c:
                try:
                    begin_write(c)
                    cp = _do(c)
                    c.commit()
                except BaseException:
                    c.rollback()
                    raise
        self._last_checkpoint_seq = max(self._last_checkpoint_seq, seq)
        return cp

    def _anchor(self, cp: Checkpoint) -> Checkpoint:
        """Write the signed checkpoint document to every provider and record
        which accepted it. Never raises: an anchor failure must not break the
        append path; it is visible in the checkpoint row and in verification."""
        if self._anchor_store is None or not self.settings.audit_anchor_checkpoints:
            return cp
        try:
            result = self._anchor_store.put_anchor(anchor_key(cp.kind, cp.seq, self.log_id), cp.document())
            anchors = {str(k): bool(v) for k, v in (result or {}).items()}
        except Exception:
            self.anchor_failures += 1
            log.warning("audit anchor write failed for checkpoint seq %s", cp.seq)
            anchors = {"_error": False}
        try:
            with self._engine.connect() as conn:
                conn.execute(update(CHECKPOINTS).where(CHECKPOINTS.c.id == cp.id)
                             .values(anchors=canonical_json(anchors)))
                conn.commit()
        except SQLAlchemyError:
            log.warning("could not store anchor status for checkpoint seq %s", cp.seq)
        return Checkpoint(**{**cp.to_dict(), "anchors": anchors})

    def create_checkpoint(self, kind: str = "manual", *,
                          audit_context: AuditContext | None = None) -> Checkpoint:
        """Sign the current chain head now and anchor it.

        Checkpoint creation is not itself an event (no recursion). If
        ``audit_context`` is given, an ``audit.checkpoint`` event is recorded
        *after* the checkpoint (success or failure) on behalf of that actor."""
        if kind not in CHECKPOINT_KINDS:
            raise ValueError("unknown checkpoint kind")
        try:
            with self._lock:
                with self._engine.connect() as conn:
                    try:
                        begin_write(conn)
                        head_seq, head_hash = self._head(conn)
                        if head_seq == 0:
                            raise AuditError("the audit log is empty; nothing to checkpoint")
                        cp = self._store_checkpoint(head_seq, head_hash, kind, conn)
                        conn.commit()
                    except BaseException:
                        conn.rollback()
                        raise
            cp = self._anchor(cp)
        except Exception as exc:
            if audit_context is not None:
                self._record_housekeeping(audit_context, "audit.checkpoint", "audit:checkpoint",
                                          Outcome.ERROR, {"kind": kind,
                                                          "error_class": type(exc).__name__},
                                          Severity.WARNING)
            if isinstance(exc, SQLAlchemyError):
                raise AuditError("checkpoint could not be created") from None
            raise
        if audit_context is not None:
            self._record_housekeeping(
                audit_context, "audit.checkpoint", "audit:checkpoint", Outcome.SUCCESS,
                {"kind": kind, "seq": cp.seq, "first_seq": cp.first_seq,
                 "event_count": cp.event_count, "key_version": cp.key_version,
                 "providers": sorted(p for p, ok in cp.anchors.items() if ok)})
        return cp

    def list_checkpoints(self, limit: int = 100) -> list[Checkpoint]:
        """Newest checkpoints first."""
        limit = max(1, min(int(limit), 1000))
        with self._engine.connect() as conn:
            rows = conn.execute(select(CHECKPOINTS).order_by(CHECKPOINTS.c.seq.desc())
                                .limit(limit)).mappings().all()
        return [Checkpoint.from_row(r) for r in rows]

    def _record_housekeeping(self, ctx: AuditContext, event_type: str, action: str,
                             outcome: Outcome, details: Mapping[str, Any],
                             severity: Severity = Severity.INFO) -> AuditRecord:
        return self.record(event_type=event_type, action=action, outcome=outcome,
                           actor_id=ctx.actor_id, actor_role=ctx.actor_role,
                           resource_type="audit", severity=severity, details=details,
                           request_id=ctx.request_id, source_ip=ctx.source_ip)

    # ================================================================== #
    # Verification
    # ================================================================== #
    def _verify_cp_signature(self, cp: Checkpoint) -> bool:
        try:
            sig = bytes.fromhex(cp.signature)
            return bool(self._kms.verify(cp.payload().encode("ascii"), sig,
                                         purpose=KeyPurpose.AUDIT_SIGNING,
                                         key_id=cp.key_id, version=int(cp.key_version)))
        except Exception:
            return False

    @staticmethod
    def _checkpoint_from_document(data: bytes) -> Checkpoint | None:
        """Parse an anchor document; None if it is not well-formed."""
        try:
            doc = json.loads(data.decode("ascii"))
            payload = json.loads(doc["payload"])
            if set(payload) != set(CHECKPOINT_PAYLOAD_FIELDS) or payload["v"] != CHECKPOINT_VERSION:
                return None
            cp = Checkpoint(id="", seq=int(payload["seq"]), head_hash=str(payload["head_hash"]),
                            ts=str(payload["ts"]), kind=str(payload["kind"]),
                            key_id=str(doc["key_id"]), key_version=int(doc["key_version"]),
                            signature=str(doc["signature"]),
                            event_count=int(payload["event_count"]),
                            first_seq=int(payload["first_seq"]))
            # the stored payload must be exactly the canonical form we would sign
            if cp.payload() != doc["payload"]:
                return None
            return cp
        except (ValueError, KeyError, TypeError, UnicodeDecodeError, AttributeError):
            return None

    def verify_chain(
        self,
        *,
        from_seq: int | None = None,
        to_seq: int | None = None,
        check_anchors: bool = True,
        batch_size: int = VERIFY_BATCH_SIZE,
        max_findings: int | None = None,
        audit_context: AuditContext | None = None,
    ) -> VerificationReport:
        """Verify the hash chain, checkpoints and anchors.

        Streams events in ``batch_size`` batches (keyset pagination) and
        reports every finding (unless ``max_findings`` caps the list, in which
        case ``findings_truncated`` is set and ``ok`` is still computed from
        everything). See NOTES.md for the finding types and the limits."""
        started = time.perf_counter()
        findings: list[Finding] = []
        state = {"truncated": False, "failing": False}

        def add(ftype: str, seq: int | None, detail: str) -> None:
            if ftype not in INFORMATIONAL_FINDINGS:
                state["failing"] = True
            if max_findings is not None and len(findings) >= max_findings:
                state["truncated"] = True
                return
            findings.append(Finding(ftype, seq, detail))

        # ---- 1. checkpoints from the DB ------------------------------------
        with self._engine.connect() as conn:
            cp_rows = conn.execute(select(CHECKPOINTS).order_by(CHECKPOINTS.c.seq.asc(),
                                                                CHECKPOINTS.c.ts.asc())
                                   ).mappings().all()
            global_head = conn.execute(select(func.max(EVENTS.c.seq))).scalar()
            global_first = conn.execute(select(func.min(EVENTS.c.seq))).scalar()
        db_cps = [Checkpoint.from_row(r) for r in cp_rows]
        trusted: dict[tuple[str, int], Checkpoint] = {}
        for cp in db_cps:
            if not self._verify_cp_signature(cp) or not _SHA256_HEX_RE.match(cp.head_hash):
                add("checkpoint-signature-invalid", cp.seq,
                    f"checkpoint {cp.kind}@{cp.seq} signature does not verify")
                continue
            trusted[(self._anchor_stem(cp.kind), cp.seq)] = cp
        checkpoints_checked = len(db_cps)

        # ---- 2. anchors ------------------------------------------------------
        anchors_checked = 0
        if check_anchors and self._anchor_store is not None:
            anchors_checked = self._check_anchors(db_cps, trusted, global_first, add)

        trusted_list = sorted(trusted.values(), key=lambda c: c.seq)
        cps_by_seq: dict[int, list[Checkpoint]] = {}
        for cp in trusted_list:
            cps_by_seq.setdefault(cp.seq, []).append(cp)
        retention_cps = [c for c in trusted_list if c.kind == "retention"]

        # ---- 3. stream events --------------------------------------------------
        events_checked = 0
        first_seen: int | None = None
        prev_seq: int | None = None
        prev_hash_stored: str | None = None
        prev_ts: str | None = None
        last_cursor = (int(from_seq) - 1) if from_seq is not None else None
        while True:
            stmt = select(EVENTS).order_by(EVENTS.c.seq.asc()).limit(batch_size)
            if last_cursor is not None:
                stmt = stmt.where(EVENTS.c.seq > last_cursor)
            if to_seq is not None:
                stmt = stmt.where(EVENTS.c.seq <= int(to_seq))
            with self._engine.connect() as conn:
                rows = conn.execute(stmt).mappings().all()
            if not rows:
                break
            for row in rows:
                seq = int(row["seq"])
                events_checked += 1
                # (a) the record itself
                try:
                    recomputed = compute_hash(row)
                except (ValueError, TypeError, KeyError):
                    recomputed = None
                if recomputed is None or recomputed != row["hash"]:
                    add("record-modified", seq,
                        "stored hash does not match the recomputed hash of the record")
                # (b) the link to its predecessor
                if prev_seq is None:
                    first_seen = seq
                    self._check_start(row, from_seq, retention_cps, add)
                else:
                    if seq <= prev_seq:     # defensive: impossible with ORDER BY on a PK
                        add("sequence-out-of-order", seq, f"seq {seq} follows seq {prev_seq}")
                    elif seq != prev_seq + 1:
                        add("sequence-gap", prev_seq + 1,
                            f"records {prev_seq + 1}..{seq - 1} are missing")
                    if row["prev_hash"] != prev_hash_stored:
                        add("chain-broken", seq, "prev_hash does not equal the previous "
                                                 f"record's hash (seq {prev_seq})")
                        self._check_reordered(row, add)
                    if prev_ts is not None and str(row["ts"]) < prev_ts:
                        add("timestamp-regression", seq, "timestamp earlier than predecessor")
                # (c) signed checkpoints at this position
                for cp in cps_by_seq.get(seq, ()):
                    if cp.head_hash != row["hash"]:
                        add("checkpoint-mismatch", seq,
                            f"{cp.kind} checkpoint head_hash differs from the chain at seq {seq}")
                prev_seq, prev_hash_stored, prev_ts = seq, row["hash"], str(row["ts"])
            last_cursor = int(rows[-1]["seq"])
            if len(rows) < batch_size:
                break

        # ---- 4. truncation / missing records at checkpoint positions ----------
        head = int(global_head) if global_head is not None else None
        for cp in trusted_list:
            if head is None:
                # empty log: legitimate only if the newest trusted checkpoint is a
                # retention checkpoint (everything pruned) and nothing is newer
                if not (retention_cps and cp.seq <= retention_cps[-1].seq):
                    add("truncated", cp.seq, f"{cp.kind} checkpoint at seq {cp.seq} "
                                             "but the audit log is empty")
            elif cp.seq > head:
                add("truncated", cp.seq, f"{cp.kind} checkpoint at seq {cp.seq} is beyond "
                                         f"the current head seq {head}: tail deleted")

        report = VerificationReport(
            ok=not state["failing"],
            events_checked=events_checked,
            first_seq=first_seen,
            last_seq=prev_seq,
            head_hash=prev_hash_stored,
            checkpoints_checked=checkpoints_checked,
            anchors_checked=anchors_checked,
            findings=findings,
            findings_truncated=state["truncated"],
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
        )
        if audit_context is not None:
            ftypes = sorted({f.type for f in findings})
            self._record_housekeeping(
                audit_context, "audit.verify", "audit:verify",
                Outcome.SUCCESS if report.ok else Outcome.FAILURE,
                {"ok": report.ok, "events_checked": events_checked,
                 "checkpoints_checked": checkpoints_checked, "anchors_checked": anchors_checked,
                 "first_seq": first_seen, "last_seq": prev_seq, "count": len(findings),
                 "finding_types": ftypes, "duration_ms": report.duration_ms},
                Severity.INFO if report.ok else Severity.CRITICAL)
        return report

    @staticmethod
    def _anchor_stem(kind: str) -> str:
        return "retention" if kind == "retention" else "checkpoint"

    def _check_start(self, row: Mapping[str, Any], from_seq: int | None,
                     retention_cps: list[Checkpoint], add) -> None:
        """Check how the first record in range links backwards.

        * seq 1 must link to genesis;
        * in a partial range, a predecessor still in the DB must match;
        * otherwise the records before it were pruned, which is legitimate
          only if a signed retention checkpoint sits exactly at seq-1 and its
          head_hash equals this record's prev_hash."""
        seq = int(row["seq"])
        if from_seq is not None and seq > int(from_seq):
            add("sequence-gap", int(from_seq), f"records {from_seq}..{seq - 1} are missing")
        if seq == 1:
            if row["prev_hash"] != GENESIS_HASH:
                add("genesis-invalid", seq, "first record does not link to the genesis hash")
            return
        with self._engine.connect() as conn:
            pred = conn.execute(select(EVENTS.c.hash).where(EVENTS.c.seq == seq - 1)).first()
        if pred is not None:
            if pred[0] != row["prev_hash"]:
                add("chain-broken", seq, f"prev_hash does not equal the hash of seq {seq - 1}")
            return
        boundary = [c for c in retention_cps if c.seq == seq - 1]
        if not boundary:
            covering = [c for c in retention_cps if c.seq < seq]
            hint = (f"latest retention checkpoint is at seq {covering[-1].seq}"
                    if covering else "no retention checkpoint exists")
            add("genesis-invalid", seq,
                f"first retained record is seq {seq} but {hint}: records were deleted "
                "outside retention")
        elif boundary[-1].head_hash != row["prev_hash"]:
            add("genesis-invalid", seq,
                "first retained record does not link to the signed retention checkpoint")

    def _check_reordered(self, row: Mapping[str, Any], add) -> None:
        """On a broken link, see whether the record links to some other
        record (rows moved/swapped), using the hash index."""
        with self._engine.connect() as conn:
            other = conn.execute(select(EVENTS.c.seq).where(EVENTS.c.hash == row["prev_hash"])
                                 .limit(1)).first()
        if other is not None and int(other[0]) != int(row["seq"]) - 1:
            add("reordered", int(row["seq"]),
                f"record links to the record now stored at seq {other[0]}")

    def _check_anchors(self, db_cps: list[Checkpoint],
                       trusted: dict[tuple[str, int], Checkpoint],
                       first_retained: int | None, add) -> int:
        """Compare provider anchor copies with DB checkpoints, and add every
        validly signed anchor to ``trusted`` (so deleting checkpoint rows does
        not hide a truncation). Returns the number of anchor copies checked."""
        store = self._anchor_store
        try:
            log_id = self.log_id
            listing = store.list_anchors(anchor_prefix(log_id)) or {}
        except Exception:
            add("anchor-unavailable", None, "anchor listing failed")
            return 0
        providers = sorted(listing)
        keys: set[str] = set()
        for prov in providers:
            for key in listing.get(prov) or []:
                m = _ANCHOR_KEY_RE.match(key)
                # only this log's namespace: another deployment's anchors in a
                # shared bucket are neither trusted nor reported (F4)
                if m and m.group(1) == log_id:
                    keys.add(key)
        # DB checkpoints that should have anchors
        db_by_key = {anchor_key(cp.kind, cp.seq, log_id): cp for cp in db_cps}
        keys.update(db_by_key)
        checked = 0
        for key in sorted(keys):
            m = _ANCHOR_KEY_RE.match(key)
            stem, seq = m.group(2), int(m.group(3))
            try:
                copies = store.get_anchor(key) or {}
            except Exception:
                add("anchor-unavailable", seq, "anchor read failed")
                continue
            db_cp = db_by_key.get(key)
            present = {p: d for p, d in copies.items() if d is not None}
            missing = [p for p in providers if p not in present]
            if db_cp is not None and present and missing:
                add("anchor-missing", seq, f"anchor absent on: {', '.join(sorted(missing))}")
            elif db_cp is not None and not present and providers:
                add("anchor-missing", seq, "no provider holds an anchor for this checkpoint")
            valid_anchor: Checkpoint | None = None
            for prov, data in sorted(present.items()):
                checked += 1
                acp = self._checkpoint_from_document(data)
                if (acp is None or self._anchor_stem(acp.kind) != stem or acp.seq != seq
                        or not self._verify_cp_signature(acp)):
                    add("anchor-mismatch", seq, f"anchor on {prov} is malformed or its "
                                                "signature does not verify")
                    continue
                if db_cp is not None and (acp.payload() != db_cp.payload()
                                          or acp.signature != db_cp.signature):
                    add("anchor-mismatch", seq,
                        f"anchor on {prov} differs from the database checkpoint")
                if valid_anchor is not None and valid_anchor.payload() != acp.payload():
                    add("anchor-mismatch", seq, "providers hold different signed checkpoints")
                valid_anchor = valid_anchor or acp
            if valid_anchor is None:
                continue
            tkey = (stem, seq)
            if tkey not in trusted:
                pruned = (first_retained is not None and seq < first_retained
                          and stem != "retention")
                if db_cp is None and not pruned:
                    add("checkpoint-missing", seq, "a signed anchor exists but the database "
                                                   "checkpoint row is missing")
                if not pruned:
                    trusted[tkey] = valid_anchor
            elif trusted[tkey].payload() != valid_anchor.payload():
                # DB checkpoint signed validly but differs from the anchor: both
                # are compared to the chain; the mismatch is already reported.
                trusted[(stem + "#anchor", seq)] = valid_anchor  # type: ignore[index]
        return checked

    # ================================================================== #
    # Retention
    # ================================================================== #
    def apply_retention(self, now: datetime | None = None, *,
                        audit_context: AuditContext | None = None) -> RetentionResult:
        """Delete events older than ``audit_retention_days`` behind a signed
        retention checkpoint. See ``app.audit.retention.apply_retention``."""
        from app.audit.retention import apply_retention
        return apply_retention(self, now=now, audit_context=audit_context)

    # ================================================================== #
    # Query (delegation)
    # ================================================================== #
    def search(self, **filters: Any) -> tuple[list[dict[str, Any]], int]:
        """See ``AuditQuery.search``."""
        return self._query.search(**filters)

    def get_event(self, seq: int) -> dict[str, Any] | None:
        return self._query.get_event(seq)

    def stats(self, since: datetime | str | None = None) -> dict[str, Any]:
        return self._query.stats(since)

    def recent_security_events(self, limit: int = 50, *, severity: str | None = None,
                               actors: "Iterable[str] | None" = None) -> list[dict[str, Any]]:
        return self._query.recent_security_events(limit, severity=severity, actors=actors)

    def export_ndjson(self, from_seq: int | None = None, to_seq: int | None = None, *,
                      actors: "Iterable[str] | None" = None) -> Iterator[str]:
        return self._query.export_ndjson(from_seq, to_seq, actors=actors)
