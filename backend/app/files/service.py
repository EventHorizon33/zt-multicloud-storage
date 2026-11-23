"""File workflow service: upload / list / metadata / download / delete /
share / verify / repair (ARCHITECTURE §3, state machine ``models.FileStatus``).

Security properties:
  * Every operation on a file goes through the PEP first. Unknown file ids
    and ids the caller may not touch both raise ``NotFound`` for callers that
    are neither owner, grantee nor admin, so existence is not revealed; the
    deny is still audited (by the PEP, or here for unknown ids).
  * Upload: the file row is ``PENDING`` -> ``UPLOADING`` (committed) before
    any chunk is stored, and every chunk id is recorded *before* its store
    call (intent log), so a crash leaves a visible, non-committed row whose
    objects the recovery pass can find and delete. The manifest, wrapped DEK
    and ``COMMITTED`` status are written in ONE transaction. On any failure
    the stored objects are deleted (best effort; leftovers are recorded and
    retried), the row becomes ``FAILED`` with a sanitised reason code and no
    key material, and ``file.upload`` failure is audited.
  * Download: plaintext is written to a spool that is handed out ONLY if the
    assembler returned ``AssemblyResult`` (ADR-0005); on any exception the
    spool is closed (it is an unlinked temp file once it exceeds the memory
    threshold). The manifest MAC is verified before any chunk is fetched, the
    stored metadata blob is compared to the manifest's ``enc_metadata_sha256``
    before it is decrypted, and every chunk is checked against its manifest
    SHA-256 by the orchestrator (replica failover) and again by the engine.
  * Delete: ``DELETING`` -> provider deletes -> the wrapped DEK is destroyed
    (crypto-shred) even if some provider deletes fail -> ``DELETED``.
    Leftover replicas are recorded and retried by maintenance.
  * Filenames are never used as paths or object keys; they are stored only
    inside the AES-GCM metadata blob and never written to the audit log.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import tempfile
import unicodedata
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import IO, Any, Callable, Iterable

from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session as DbSession

from app.config import Settings
from app.contracts import (Action, AuditSink, Classification, Outcome, RequestContext, Resource, Role,
                           Severity, StorageError, Subject)
from app.cryptoengine import CryptoEngine, MetadataIntegrityError, PlaintextAccumulator
from app.errors import (AccessDenied, AppError, Conflict, DataUnavailable, IntegrityError, KmsError,
                        ManifestIntegrityError, NotFound, UploadFailed, ValidationFailed)
from app.models import Chunk, ChunkReplica, File, FileShare, FileStatus, ReplicaStatus, User, new_id

log = logging.getLogger("zt.files")

Clock = Callable[[], datetime]

FILE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_MIME_RE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,127}$")
MAX_FILENAME_CHARS = 255
MAX_FILENAME_BYTES = 1024
DEFAULT_MIME = "application/octet-stream"
DEFAULT_CLASSIFICATION = Classification.INTERNAL
DEFAULT_SPOOL_BYTES = 8 * 1024 * 1024
#: replica rows in this state are objects we failed to delete; maintenance retries them
LEFTOVER = ReplicaStatus.FAILED


# --------------------------------------------------------------------------- #
# input sanitation
# --------------------------------------------------------------------------- #
def sanitize_filename(name: Any) -> str:
    """Display name only (never a path): last path component, NFC, without
    control/format characters (incl. bidi overrides), 1..255 chars."""
    if not isinstance(name, str):
        raise ValidationFailed("invalid filename", reasons=("invalid-filename",))
    name = unicodedata.normalize("NFC", name).replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(ch for ch in name if unicodedata.category(ch)[0] not in ("C",)).strip()
    if name in ("", ".", "..") or len(name) > MAX_FILENAME_CHARS \
            or len(name.encode("utf-8")) > MAX_FILENAME_BYTES:
        raise ValidationFailed("invalid filename", reasons=("invalid-filename",))
    return name


def sanitize_mime(mime: Any) -> str:
    """``type/subtype`` lower-cased without parameters; anything else becomes
    application/octet-stream (the value is informational only: downloads are
    always served as octet-stream attachments)."""
    if not isinstance(mime, str):
        return DEFAULT_MIME
    base = mime.split(";", 1)[0].strip().lower()
    return base if _MIME_RE.match(base) else DEFAULT_MIME


def parse_classification(value: Any) -> Classification:
    if value is None or value == "":
        return DEFAULT_CLASSIFICATION
    try:
        return Classification(value)
    except ValueError:
        raise ValidationFailed("invalid classification", reasons=("invalid-classification",)) from None


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    v = _utc(value)
    return v.isoformat().replace("+00:00", "Z") if v is not None else None


def _reason_code(exc: BaseException) -> str:
    """Sanitised, fixed-vocabulary failure reason (never an exception message)."""
    if isinstance(exc, ValidationFailed):
        return (exc.reasons[0] if exc.reasons else exc.code)[:64]
    if isinstance(exc, StorageError):
        return "storage-unavailable"
    if isinstance(exc, AppError):
        return exc.code
    name = type(exc).__name__
    if name in ("ClientDisconnect", "UploadAborted"):
        return "client-aborted"
    if name == "BodyTooLarge":
        return "upload-too-large"
    return "internal-error"


@dataclass
class DownloadHandle:
    """A fully verified download. ``stream`` is positioned at 0 and must be
    closed by the caller."""
    file_id: str
    filename: str
    mime_type: str
    size_bytes: int
    plaintext_sha256: str
    stream: IO[bytes]


class FileService:
    def __init__(self, *, settings: Settings, crypto: CryptoEngine, orchestrator: Any, pep: Any,
                 audit: AuditSink, detector: Any, policy_store: Any, clock: Clock,
                 stale_upload_minutes: float = 10.0, spool_threshold_bytes: int = DEFAULT_SPOOL_BYTES) -> None:
        self._settings = settings
        self._crypto = crypto
        self._orch = orchestrator
        self._pep = pep
        self._audit = audit
        self._detector = detector
        self._policy = policy_store
        self._clock = clock
        self.stale_upload_minutes = float(stale_upload_minutes)
        self.spool_threshold_bytes = int(spool_threshold_bytes)
        self._spool_dir = settings.data_dir / "tmp"

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    def _now(self) -> datetime:
        return _utc(self._clock())  # type: ignore[return-value]

    def _record(self, event: str, action: Action | str, outcome: Outcome, subject: Subject | None,
                context: RequestContext | None, *, file_id: str | None = None, reason: str | None = None,
                severity: Severity = Severity.INFO, details: dict | None = None) -> None:
        self._audit.record(
            event_type=event, action=getattr(action, "value", action), outcome=outcome,
            actor_id=subject.user_id if subject else None,
            actor_role=subject.role.value if subject else None,
            resource_type="file", resource_id=file_id, reason=reason, severity=severity,
            details=details, request_id=context.request_id if context else None,
            source_ip=context.source_ip if context else None)

    @staticmethod
    def _load(db: DbSession, file_id: str) -> File | None:
        return db.execute(select(File).where(File.id == file_id)
                          .execution_options(populate_existing=True)).scalar_one_or_none()

    @staticmethod
    def _shared_with(db: DbSession, file_id: str, user_id: str) -> bool:
        return db.execute(select(FileShare.id).where(
            FileShare.file_id == file_id, FileShare.grantee_id == user_id,
            FileShare.revoked_at.is_(None)).limit(1)).first() is not None

    @staticmethod
    def _classification(row: File) -> Classification | None:
        try:
            return Classification(row.classification)
        except ValueError:
            return None            # PDP fails closed (classification-missing)

    def _resource(self, row: File, shared: bool) -> Resource:
        return Resource(type="file", id=row.id, owner_id=row.owner_id,
                        classification=self._classification(row), shared_with_subject=shared,
                        status=row.status)

    def _authorize(self, db: DbSession, subject: Subject, action: Action, file_id: Any,
                   context: RequestContext, *, prepare: Callable[[File, bool, RequestContext],
                                                                 RequestContext] | None = None
                   ) -> tuple[File, bool]:
        """Load + PEP. Returns (row, shared). Unknown/deleted ids and denied
        ids of non-parties raise NotFound; all denies are audited."""
        row = self._load(db, file_id) if isinstance(file_id, str) and FILE_ID_RE.match(file_id) else None
        if row is None or row.status == FileStatus.DELETED:
            self._audit.record(
                event_type="authz.decision", action=action.value, outcome=Outcome.DENIED,
                actor_id=subject.user_id, actor_role=subject.role.value, resource_type="file",
                resource_id=file_id if isinstance(file_id, str) and FILE_ID_RE.match(file_id) else None,
                reason="not-found", severity=Severity.WARNING, details={"reasons": ["not-found"]},
                request_id=context.request_id, source_ip=context.source_ip)
            raise NotFound("file not found")
        shared = self._shared_with(db, row.id, subject.user_id)
        is_owner = hmac.compare_digest(row.owner_id, subject.user_id)
        if prepare is not None:
            context = prepare(row, shared or is_owner, context)
        try:
            self._pep.enforce(db, subject, action, self._resource(row, shared), context)
        except AccessDenied:
            if is_owner or shared or subject.role is Role.ADMIN:
                raise
            raise NotFound("file not found") from None
        return row, shared

    def _open(self, row: File):
        """(keys, verified manifest). Raises IntegrityError subclasses."""
        if not row.wrapped_dek or not row.manifest_json or not row.manifest_mac:
            raise ManifestIntegrityError("file has no key or manifest", reasons=("manifest-missing",))
        try:
            keys = self._crypto.load_file_keys(row.id, row.owner_id, row.wrapped_dek)
        except KmsError:
            # wrapped key moved to another row, owner changed, or blob modified
            raise IntegrityError("data key could not be unwrapped", reasons=("key-unwrap-failed",)) from None
        try:
            manifest = self._crypto.open_manifest(keys, row.manifest_json, row.manifest_mac,
                                                  expected_file_id=row.id, expected_owner_id=row.owner_id)
        except BaseException:
            keys.destroy()
            raise
        if manifest.get("classification") != row.classification:
            keys.destroy()
            raise ManifestIntegrityError("classification differs from the manifest",
                                         reasons=("manifest-classification-mismatch",))
        return keys, manifest

    def _metadata(self, row: File, keys, manifest: dict) -> dict[str, str]:
        """Decrypt filename/MIME after checking the blob against the manifest."""
        blob = row.enc_metadata or b""
        expected = str(manifest.get("enc_metadata_sha256", ""))
        if not blob or not hmac.compare_digest(hashlib.sha256(blob).hexdigest().encode(),
                                               expected.encode("utf-8", "replace")):
            raise IntegrityError("metadata blob does not match the manifest",
                                 reasons=("metadata-hash-mismatch",))
        try:
            return self._crypto.decrypt_metadata(keys, row.id, blob)
        except MetadataIntegrityError:
            raise IntegrityError("metadata failed authentication", reasons=("metadata-auth-failed",)) from None

    def _integrity_failure(self, exc: IntegrityError, subject: Subject | None, context: RequestContext | None,
                           row: File, action: Action) -> None:
        reasons = list(getattr(exc, "reasons", ()) or (exc.code,))
        try:
            self._record("file.integrity", action, Outcome.FAILURE, subject, context, file_id=row.id,
                         reason=reasons[0], severity=Severity.CRITICAL, details={"reasons": reasons})
        except Exception:  # the operation fails anyway; do not mask the integrity error
            log.error("could not audit an integrity failure")

    def _set_replica(self, db: DbSession, chunk_id: str, provider: str, status: str, *,
                     now: datetime | None = None, verified: bool = False) -> None:
        rep = db.execute(select(ChunkReplica).where(ChunkReplica.chunk_id == chunk_id,
                                                    ChunkReplica.provider == provider)).scalar_one_or_none()
        if rep is None:
            if db.get(Chunk, chunk_id) is None:
                return
            rep = ChunkReplica(chunk_id=chunk_id, provider=provider)
            db.add(rep)
        rep.status = status
        if status == ReplicaStatus.STORED and now is not None and rep.stored_at is None:
            rep.stored_at = now
        if verified and now is not None:
            rep.last_verified_at = now

    # ------------------------------------------------------------------ #
    # views
    # ------------------------------------------------------------------ #
    def _owner_username(self, db: DbSession, owner_id: str) -> str | None:
        u = db.get(User, owner_id)
        return u.username if u is not None else None

    def _view(self, db: DbSession, row: File, subject: Subject, shared: bool, *,
              names: bool) -> dict[str, Any]:
        is_owner = hmac.compare_digest(row.owner_id, subject.user_id)
        view: dict[str, Any] = {
            "id": row.id, "filename": None, "mime_type": None, "size_bytes": row.size_bytes,
            "classification": row.classification, "status": row.status, "chunk_count": row.chunk_count,
            "chunk_size": row.chunk_size, "created_at": _iso(row.created_at),
            "committed_at": _iso(row.committed_at), "owner_id": row.owner_id,
            "owner_username": self._owner_username(db, row.owner_id), "is_owner": is_owner,
            "shared_with_me": bool(shared and not is_owner), "failure_reason": row.failure_reason,
            "metadata_error": None,
        }
        if names and (is_owner or shared) and row.status == FileStatus.COMMITTED:
            try:
                keys, manifest = self._open(row)
                try:
                    meta = self._metadata(row, keys, manifest)
                finally:
                    keys.destroy()
                view["filename"] = meta.get("filename")
                view["mime_type"] = meta.get("mime_type")
            except IntegrityError as exc:
                view["metadata_error"] = "integrity-failure"
                self._integrity_failure(exc, subject, None, row, Action.FILE_READ_METADATA)
        return view

    # ------------------------------------------------------------------ #
    # upload
    # ------------------------------------------------------------------ #
    def upload(self, db: DbSession, subject: Subject, stream: Any, *, filename: Any, mime_type: Any,
               classification: Any, context: RequestContext) -> dict[str, Any]:
        name = sanitize_filename(filename)
        mime = sanitize_mime(mime_type)
        cls = parse_classification(classification)
        owner_id = subject.user_id
        self._pep.enforce(db, subject, Action.FILE_CREATE,
                          Resource(type="file", owner_id=owner_id, classification=cls), context)
        now = self._now()
        row = File(id=new_id(), owner_id=owner_id, status=FileStatus.PENDING, classification=cls.value,
                   chunk_size=self._crypto.chunk_size, created_at=now)
        db.add(row)
        db.commit()
        file_id = row.id
        stored: dict[str, list[str]] = {}   # chunk id -> providers holding a replica
        keys = None
        try:
            row.status = FileStatus.UPLOADING
            db.commit()
            keys, dk = self._crypto.new_file_keys(file_id, owner_id)
            acc = PlaintextAccumulator()
            entries: list[dict] = []
            for ch in self._crypto.encrypt_stream(keys, file_id, stream, accumulator=acc,
                                                  max_bytes=int(self._settings.max_upload_bytes)):
                # intent log: the id is durable BEFORE anything reaches a provider
                db.add(Chunk(id=ch.chunk_id, file_id=file_id, index=ch.index,
                             ciphertext_size=ch.size, ciphertext_sha256=ch.sha256_hex))
                db.commit()
                res = self._orch.store_chunk(file_id, ch.chunk_id, ch.index, ch.blob, ch.sha256_hex)
                stored[ch.chunk_id] = list(res.stored_on)
                t = self._now()
                for p in res.stored_on:
                    db.add(ChunkReplica(chunk_id=ch.chunk_id, provider=p, status=ReplicaStatus.STORED,
                                        stored_at=t))
                db.commit()
                entries.append(ch.manifest_entry(res.stored_on))
            enc_meta = self._crypto.encrypt_metadata(keys, file_id, {
                "filename": name, "mime_type": mime, "plaintext_sha256": acc.plaintext_sha256})
            manifest = self._crypto.build_manifest(
                file_id=file_id, owner_id=owner_id, classification=cls.value, size_bytes=acc.size_bytes,
                plaintext_sha256=acc.plaintext_sha256,
                enc_metadata_sha256=hashlib.sha256(enc_meta).hexdigest(), kek_id=dk.key_id,
                kek_version=dk.key_version, chunks=entries, created_at=now)
            manifest_json, manifest_mac = self._crypto.seal_manifest(keys, manifest)
            # ---- single commit transaction ----
            row.size_bytes = acc.size_bytes
            row.chunk_count = len(entries)
            row.wrapped_dek = dk.wrapped
            row.kek_id = dk.key_id
            row.kek_version = dk.key_version
            row.enc_metadata = enc_meta
            row.manifest_json = manifest_json
            row.manifest_mac = manifest_mac
            row.status = FileStatus.COMMITTED
            row.committed_at = self._now()
            row.failure_reason = None
            db.flush()
            self._record("chunk.create", Action.FILE_CREATE, Outcome.SUCCESS, subject, context,
                         file_id=file_id, details={"chunk_count": len(entries), "size_bytes": acc.size_bytes})
            self._record("file.upload", Action.FILE_CREATE, Outcome.SUCCESS, subject, context,
                         file_id=file_id, details={"chunk_count": len(entries), "size_bytes": acc.size_bytes,
                                                   "classification": cls.value})
            db.commit()
        except BaseException as exc:
            try:
                db.rollback()
            except Exception:  # pragma: no cover
                pass
            self._fail_upload(db, file_id, stored, exc, subject, context)
            if isinstance(exc, AppError):
                raise
            if isinstance(exc, StorageError):
                raise UploadFailed("upload failed", reasons=("storage-unavailable",)) from None
            raise
        finally:
            if keys is not None:
                keys.destroy()
        return self._view(db, row, subject, False, names=False) | {"filename": name, "mime_type": mime}

    def _fail_upload(self, db: DbSession, file_id: str, stored: dict[str, list[str]], exc: BaseException,
                     subject: Subject, context: RequestContext) -> None:
        """Best-effort cleanup; never raises."""
        reason = _reason_code(exc)
        leftovers = 0
        try:
            leftover_map: dict[str, list[str]] = {}
            cleanup_failed = getattr(exc, "cleanup_failed", None)
            if cleanup_failed and getattr(exc, "chunk_id", None):
                leftover_map[exc.chunk_id] = list(cleanup_failed)       # type: ignore[attr-defined]
            for chunk_id, providers in stored.items():
                if not providers:
                    continue
                res = self._orch.delete_chunk(chunk_id, providers)
                for p in res.deleted:
                    self._set_replica(db, chunk_id, p, ReplicaStatus.DELETED)
                for f in res.failed:
                    leftover_map.setdefault(chunk_id, []).append(f.provider)
            for chunk_id, providers in leftover_map.items():
                for p in providers:
                    leftovers += 1
                    self._set_replica(db, chunk_id, p, LEFTOVER)
            db.commit()
        except Exception:
            db.rollback()
            log.error("upload cleanup failed for a file (%s)", reason)
        try:
            db.execute(update(File).where(File.id == file_id).values(
                status=FileStatus.FAILED, failure_reason=reason, wrapped_dek=None, enc_metadata=None,
                manifest_json=None, manifest_mac=None, kek_id=None, kek_version=None))
            db.commit()
        except Exception:
            db.rollback()
            log.error("could not mark an upload as failed (%s)", reason)
        try:
            outcome = Outcome.FAILURE if isinstance(exc, ValidationFailed) else Outcome.ERROR
            self._record("file.upload", Action.FILE_CREATE, outcome, subject, context, file_id=file_id,
                         reason=reason, severity=Severity.WARNING,
                         details={"chunk_count": len(stored), "leftover_replicas": leftovers})
        except Exception:
            log.error("could not audit a failed upload (%s)", reason)

    # ------------------------------------------------------------------ #
    # list / metadata
    # ------------------------------------------------------------------ #
    def list_files(self, db: DbSession, subject: Subject, context: RequestContext, *,
                   include_failed: bool = True) -> list[dict[str, Any]]:
        """Own files (any status except deleted) + COMMITTED files shared with
        the caller. Each row is filtered through the PDP (read-metadata)."""
        self._pep.enforce(db, subject, Action.FILE_LIST, Resource(type="file", owner_id=subject.user_id),
                          context)
        shared_ids = select(FileShare.file_id).where(FileShare.grantee_id == subject.user_id,
                                                     FileShare.revoked_at.is_(None))
        own_statuses = [s for s in (FileStatus.COMMITTED, FileStatus.UPLOADING, FileStatus.PENDING,
                                    FileStatus.FAILED, FileStatus.DELETING)
                        if include_failed or s == FileStatus.COMMITTED]
        rows = db.execute(select(File).where(or_(
            (File.owner_id == subject.user_id) & File.status.in_(own_statuses),
            File.id.in_(shared_ids) & (File.status == FileStatus.COMMITTED),
        )).order_by(File.created_at.desc())).scalars().all()
        out = []
        for row in rows:
            shared = row.owner_id != subject.user_id
            if not self._pep.check(db, subject, Action.FILE_READ_METADATA, self._resource(row, shared),
                                   context).allow:
                continue
            out.append(self._view(db, row, subject, shared, names=True))
        return out

    def admin_list_files(self, db: DbSession, subject: Subject, context: RequestContext, *,
                         limit: int = 200, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        """Metadata-only listing over all owners (no filenames for files the
        caller is not a party to). Each row must pass FILE_READ_METADATA."""
        self._pep.enforce(db, subject, Action.FILE_LIST, Resource(type="file"), context)
        rows = db.execute(select(File).where(File.status != FileStatus.DELETED)
                          .order_by(File.created_at.desc())).scalars().all()
        visible = []
        for row in rows:
            shared = self._shared_with(db, row.id, subject.user_id)
            if self._pep.check(db, subject, Action.FILE_READ_METADATA, self._resource(row, shared),
                               context).allow:
                visible.append((row, shared))
        total = len(visible)
        out = [self._view(db, row, subject, shared, names=False)
               for row, shared in visible[offset:offset + limit]]
        return out, int(total)

    def get_metadata(self, db: DbSession, subject: Subject, file_id: Any,
                     context: RequestContext) -> dict[str, Any]:
        row, shared = self._authorize(db, subject, Action.FILE_READ_METADATA, file_id, context)
        return self._view(db, row, subject, shared, names=True)

    def distribution(self, db: DbSession, subject: Subject, file_id: Any,
                     context: RequestContext) -> dict[str, Any]:
        """Chunk -> provider -> replica status (from the projection tables;
        informational, never used for reconstruction)."""
        row, _ = self._authorize(db, subject, Action.FILE_READ_METADATA, file_id, context)
        chunks = db.execute(select(Chunk).where(Chunk.file_id == row.id).order_by(Chunk.index)).scalars().all()
        per_provider: dict[str, int] = {n: 0 for n in self._orch.provider_names}
        out = []
        for ch in chunks:
            reps = sorted(ch.replicas, key=lambda r: r.provider)
            for r in reps:
                if r.status == ReplicaStatus.STORED:
                    per_provider[r.provider] = per_provider.get(r.provider, 0) + 1
            out.append({"index": ch.index, "chunk_id": ch.id, "ciphertext_size": ch.ciphertext_size,
                        "ciphertext_sha256": ch.ciphertext_sha256,
                        "replicas": [{"provider": r.provider, "status": r.status,
                                      "stored_at": _iso(r.stored_at),
                                      "last_verified_at": _iso(r.last_verified_at)} for r in reps]})
        return {"file_id": row.id, "status": row.status, "chunk_count": row.chunk_count,
                "replication_factor": self._orch.replication_factor,
                "providers": per_provider, "chunks": out}

    # ------------------------------------------------------------------ #
    # download
    # ------------------------------------------------------------------ #
    def _with_detection(self, db: DbSession, subject: Subject):
        def prepare(row: File, party: bool, context: RequestContext) -> RequestContext:
            if not party:
                return context
            sig = self._detector.evaluate(
                db, subject.user_id, size_bytes=row.size_bytes, thresholds=self._policy.load(db),
                actor_role=subject.role.value, resource_id=row.id, request_id=context.request_id,
                source_ip=context.source_ip)
            return replace(context, recent_download_count=sig.count, recent_download_bytes=sig.bytes,
                           download_blocked=sig.blocked)
        return prepare

    def download(self, db: DbSession, subject: Subject, file_id: Any, context: RequestContext) -> DownloadHandle:
        row, _ = self._authorize(db, subject, Action.FILE_READ, file_id, context,
                                 prepare=self._with_detection(db, subject))
        try:
            keys, manifest = self._open(row)
        except IntegrityError as exc:
            self._integrity_failure(exc, subject, context, row, Action.FILE_READ)
            self._record("file.download", Action.FILE_READ, Outcome.FAILURE, subject, context,
                         file_id=row.id, reason=exc.reasons[0] if exc.reasons else exc.code,
                         severity=Severity.CRITICAL)
            raise
        self._spool_dir.mkdir(parents=True, exist_ok=True)
        spool = tempfile.SpooledTemporaryFile(max_size=self.spool_threshold_bytes, dir=self._spool_dir)
        bad: list[tuple[str, str, str]] = []

        def fetch(entry: dict) -> bytes:
            sha = str(entry["sha256"])
            try:
                res = self._orch.fetch_chunk(
                    entry["id"], entry["replicas"],
                    verify=lambda d: hmac.compare_digest(hashlib.sha256(d).hexdigest(), sha))
            except StorageError as exc:
                for a in getattr(exc, "attempts", []) or []:
                    if a.outcome in ("corrupt", "missing"):
                        bad.append((entry["id"], a.provider, a.outcome))
                raise
            for a in res.attempts:
                if a.outcome in ("corrupt", "missing"):
                    bad.append((entry["id"], a.provider, a.outcome))
            return res.data

        try:
            try:
                meta = self._metadata(row, keys, manifest)
                result = self._crypto.assemble(keys, manifest, fetch, spool)
            finally:
                keys.destroy()
        except BaseException as exc:
            spool.close()               # unverified plaintext is discarded, never released
            self._mark_bad(db, bad)
            if isinstance(exc, IntegrityError):
                err: AppError = exc
            elif isinstance(exc, StorageError):
                if getattr(exc, "any_corrupt", False):
                    err = IntegrityError("no intact replica", reasons=("all-replicas-corrupt",))
                else:
                    err = DataUnavailable("chunk unavailable", reasons=("data-unavailable",))
            else:
                raise
            if isinstance(err, IntegrityError):
                self._integrity_failure(err, subject, context, row, Action.FILE_READ)
            self._record("file.download", Action.FILE_READ,
                         Outcome.FAILURE if isinstance(err, IntegrityError) else Outcome.ERROR,
                         subject, context, file_id=row.id, reason=err.reasons[0] if err.reasons else err.code,
                         severity=Severity.CRITICAL if isinstance(err, IntegrityError) else Severity.WARNING)
            if err is exc:
                raise
            raise err from None
        try:
            self._mark_bad(db, bad)
            self._detector.record(db, subject.user_id, row.id, result.size_bytes)
            self._record("file.download", Action.FILE_READ, Outcome.SUCCESS, subject, context, file_id=row.id,
                         severity=Severity.WARNING if bad else Severity.INFO,
                         details={"size_bytes": result.size_bytes, "chunk_count": result.chunk_count,
                                  "corrupt": sum(1 for b in bad if b[2] == "corrupt"),
                                  "missing": sum(1 for b in bad if b[2] == "missing")})
        except BaseException:
            spool.close()
            raise
        spool.seek(0)
        return DownloadHandle(file_id=row.id, filename=meta.get("filename", "download"),
                              mime_type=meta.get("mime_type", DEFAULT_MIME), size_bytes=result.size_bytes,
                              plaintext_sha256=result.plaintext_sha256, stream=spool)

    def _mark_bad(self, db: DbSession, bad: Iterable[tuple[str, str, str]]) -> None:
        bad = list(bad)
        if not bad:
            return
        try:
            for chunk_id, provider, outcome in bad:
                self._set_replica(db, chunk_id, provider,
                                  ReplicaStatus.CORRUPT if outcome == "corrupt" else ReplicaStatus.MISSING)
            db.commit()
        except Exception:
            db.rollback()
            log.warning("could not update replica status after a failed read")

    # ------------------------------------------------------------------ #
    # delete (crypto-shred)
    # ------------------------------------------------------------------ #
    def delete(self, db: DbSession, subject: Subject, file_id: Any, context: RequestContext) -> dict[str, Any]:
        row, _ = self._authorize(db, subject, Action.FILE_DELETE, file_id, context)
        if row.status not in (FileStatus.COMMITTED, FileStatus.FAILED):
            raise Conflict("file is busy", reasons=("file-busy",))
        claimed = db.execute(update(File).where(File.id == row.id, File.status == row.status)
                             .values(status=FileStatus.DELETING)).rowcount
        db.commit()
        if claimed != 1:
            raise Conflict("file is busy", reasons=("file-busy",))
        return self._purge(db, row.id, subject, context)

    @staticmethod
    def _manifest_replicas(manifest_json: str | None) -> dict[str, list[str]]:
        """Replica lists from the stored manifest WITHOUT MAC verification:
        used only to widen the set of objects a delete targets."""
        if not manifest_json:
            return {}
        try:
            m = json.loads(manifest_json)
            return {str(c["id"]): [str(p) for p in c.get("replicas", [])] for c in m.get("chunks", [])
                    if isinstance(c, dict) and "id" in c}
        except (ValueError, TypeError, KeyError, AttributeError):
            return {}

    def _purge(self, db: DbSession, file_id: str, subject: Subject | None,
               context: RequestContext | None) -> dict[str, Any]:
        row = self._load(db, file_id)
        assert row is not None
        targets: dict[str, set[str]] = {}
        for ch in db.execute(select(Chunk).where(Chunk.file_id == row.id)).scalars():
            targets.setdefault(ch.id, set()).update(r.provider for r in ch.replicas
                                                    if r.status != ReplicaStatus.DELETED)
        for cid, provs in self._manifest_replicas(row.manifest_json).items():
            if cid in targets:      # never delete objects this file does not own
                targets[cid].update(provs)
        leftovers = 0
        for cid, provs in targets.items():
            names = sorted(p for p in provs if p in self._orch.provider_names)
            if not names:
                continue
            res = self._orch.delete_chunk(cid, names)
            for p in res.deleted:
                self._set_replica(db, cid, p, ReplicaStatus.DELETED)
            for f in res.failed:
                leftovers += 1
                self._set_replica(db, cid, f.provider, LEFTOVER)
        now = self._now()
        revoked = db.execute(update(FileShare).where(FileShare.file_id == row.id, FileShare.revoked_at.is_(None))
                             .values(revoked_at=now)).rowcount
        # crypto-shred: without the wrapped DEK no copy of any chunk can be decrypted
        row.wrapped_dek = None
        row.enc_metadata = None
        row.manifest_json = None
        row.manifest_mac = None
        row.status = FileStatus.DELETED
        row.deleted_at = now
        try:
            db.flush()
            self._record("file.delete", Action.FILE_DELETE, Outcome.SUCCESS, subject, context, file_id=row.id,
                         severity=Severity.WARNING if leftovers else Severity.INFO,
                         details={"chunk_count": len(targets), "leftover_replicas": leftovers,
                                  "shares_revoked": int(revoked or 0)})
            db.commit()
        except BaseException:
            db.rollback()        # stays DELETING; maintenance finishes the shred
            raise
        return {"file_id": row.id, "status": FileStatus.DELETED, "leftover_replicas": leftovers}

    # ------------------------------------------------------------------ #
    # sharing
    # ------------------------------------------------------------------ #
    @staticmethod
    def _find_user(db: DbSession, username: Any) -> User | None:
        if not isinstance(username, str) or not (1 <= len(username) <= 64):
            return None
        return db.execute(select(User).where(func.lower(User.username) == username.lower())).scalar_one_or_none()

    def share(self, db: DbSession, subject: Subject, file_id: Any, username: Any,
              context: RequestContext) -> dict[str, Any]:
        row, _ = self._authorize(db, subject, Action.FILE_SHARE, file_id, context)
        if row.status != FileStatus.COMMITTED:
            raise Conflict("file is not available", reasons=("file-not-available",))
        grantee = self._find_user(db, username)
        if grantee is None or not grantee.is_active or grantee.id == subject.user_id:
            # one code for unknown / disabled / self: the API does not say which
            self._record("file.share", Action.FILE_SHARE, Outcome.FAILURE, subject, context, file_id=row.id,
                         reason="share-target-invalid", severity=Severity.WARNING)
            raise ValidationFailed("invalid share target", reasons=("share-target-invalid",))
        existing = db.execute(select(FileShare).where(
            FileShare.file_id == row.id, FileShare.grantee_id == grantee.id,
            FileShare.revoked_at.is_(None))).scalar_one_or_none()
        if existing is None:
            existing = FileShare(file_id=row.id, grantee_id=grantee.id, granted_by=subject.user_id,
                                 created_at=self._now())
            db.add(existing)
            db.flush()
            self._record("file.share", Action.FILE_SHARE, Outcome.SUCCESS, subject, context, file_id=row.id,
                         details={"target_user": self._pseudonym(grantee.id)})
            db.commit()
        return {"file_id": row.id, "username": grantee.username, "created_at": _iso(existing.created_at)}

    def _pseudonym(self, user_id: str) -> str | None:
        fn = getattr(self._audit, "pseudonym_for", None)
        return fn(user_id) if callable(fn) else None

    def unshare(self, db: DbSession, subject: Subject, file_id: Any, username: Any,
                context: RequestContext) -> None:
        row, _ = self._authorize(db, subject, Action.FILE_SHARE, file_id, context)
        grantee = self._find_user(db, username)
        n = 0
        if grantee is not None:
            n = db.execute(update(FileShare).where(
                FileShare.file_id == row.id, FileShare.grantee_id == grantee.id,
                FileShare.revoked_at.is_(None)).values(revoked_at=self._now())).rowcount
        if not n:
            db.rollback()
            raise NotFound("share not found", reasons=("share-not-found",))
        self._record("file.unshare", Action.FILE_SHARE, Outcome.SUCCESS, subject, context, file_id=row.id,
                     details={"target_user": self._pseudonym(grantee.id)})  # type: ignore[union-attr]
        db.commit()

    def list_shares(self, db: DbSession, subject: Subject, file_id: Any,
                    context: RequestContext) -> list[dict[str, Any]]:
        row, _ = self._authorize(db, subject, Action.FILE_READ_METADATA, file_id, context)
        if row.owner_id != subject.user_id:
            raise AccessDenied("only the owner can list shares", reasons=("not-owner",))
        shares = db.execute(select(FileShare, User).join(User, User.id == FileShare.grantee_id).where(
            FileShare.file_id == row.id, FileShare.revoked_at.is_(None))
            .order_by(FileShare.created_at)).all()
        return [{"username": u.username, "created_at": _iso(s.created_at)} for s, u in shares]

    # ------------------------------------------------------------------ #
    # verify / repair (no plaintext leaves)
    # ------------------------------------------------------------------ #
    def _committed_manifest(self, db, subject, action, file_id, context):
        row, _ = self._authorize(db, subject, action, file_id, context)
        if row.status != FileStatus.COMMITTED:
            raise Conflict("file is not available", reasons=("file-not-available",))
        try:
            keys, manifest = self._open(row)
        except IntegrityError as exc:
            self._integrity_failure(exc, subject, context, row, action)
            raise
        return row, keys, manifest

    def verify(self, db: DbSession, subject: Subject, file_id: Any, context: RequestContext) -> dict[str, Any]:
        """Scrub: compare every replica's SHA-256 with the MAC-verified manifest."""
        row, keys, manifest = self._committed_manifest(db, subject, Action.FILE_VERIFY, file_id, context)
        keys.destroy()       # the manifest is authenticated; no decryption follows
        now = self._now()
        counts = {"ok": 0, "corrupt": 0, "missing": 0, "unavailable": 0}
        chunks_out = []
        intact = True
        for entry in manifest["chunks"]:
            reps = []
            ok_here = 0
            for p in entry["replicas"]:
                try:
                    res = self._orch.verify_replica(p, entry["id"], entry["sha256"])
                except KeyError:
                    res = "unavailable"
                counts[res] = counts.get(res, 0) + 1
                ok_here += res == "ok"
                if res == "ok":
                    self._set_replica(db, entry["id"], p, ReplicaStatus.STORED, now=now, verified=True)
                elif res in ("corrupt", "missing"):
                    self._set_replica(db, entry["id"], p, ReplicaStatus.CORRUPT if res == "corrupt"
                                      else ReplicaStatus.MISSING, now=now, verified=True)
                reps.append({"provider": p, "result": res})
            intact = intact and ok_here > 0
            chunks_out.append({"index": entry["i"], "chunk_id": entry["id"], "replicas": reps})
        healthy = counts["corrupt"] == 0 and counts["missing"] == 0 and counts["unavailable"] == 0
        self._record("file.verify", Action.FILE_VERIFY, Outcome.SUCCESS if healthy else Outcome.FAILURE,
                     subject, context, file_id=row.id,
                     severity=Severity.INFO if healthy else (Severity.CRITICAL if counts["corrupt"]
                                                              else Severity.WARNING),
                     details={"chunk_count": len(chunks_out), "verified": counts["ok"],
                              "corrupt": counts["corrupt"], "missing": counts["missing"],
                              "unavailable": counts["unavailable"], "ok": healthy})
        db.commit()
        return {"file_id": row.id, "healthy": healthy, "recoverable": intact, "summary": counts,
                "chunks": chunks_out}

    def repair(self, db: DbSession, subject: Subject, file_id: Any, context: RequestContext) -> dict[str, Any]:
        """Re-replicate chunks with corrupt/missing/too few replicas from a
        verified replica, then re-seal the manifest (ADR-0003)."""
        row, keys, manifest = self._committed_manifest(db, subject, Action.FILE_REPAIR, file_id, context)
        R = self._orch.replication_factor
        repaired, unrepairable = [], []
        changed = False
        now = self._now()
        try:
            for entry in list(manifest["chunks"]):
                cid, sha, idx = entry["id"], entry["sha256"], entry["i"]
                results = {}
                for p in entry["replicas"]:
                    try:
                        results[p] = self._orch.verify_replica(p, cid, sha)
                    except KeyError:
                        results[p] = "unavailable"
                good = [p for p, r in results.items() if r == "ok"]
                bad = [p for p, r in results.items() if r in ("corrupt", "missing")]
                if not bad and len(good) + sum(r == "unavailable" for r in results.values()) >= R:
                    continue
                if not good:
                    unrepairable.append(idx)
                    continue
                fetched = self._orch.fetch_chunk(
                    cid, good, verify=lambda d, s=sha: hmac.compare_digest(hashlib.sha256(d).hexdigest(), s))
                new = self._orch.repair_chunk(cid, idx, row.id, fetched.data, sha, entry["replicas"], bad)
                if not new:
                    unrepairable.append(idx)
                    continue
                manifest = self._crypto.update_manifest_replicas(manifest, idx, sorted(new))
                changed = True
                repaired.append(idx)
                for p in bad:
                    if p not in new:
                        self._set_replica(db, cid, p, ReplicaStatus.DELETED)
                for p in new:
                    self._set_replica(db, cid, p, ReplicaStatus.STORED, now=now, verified=True)
            if changed:
                row.manifest_json, row.manifest_mac = self._crypto.seal_manifest(keys, manifest)
            db.flush()
            ok = not unrepairable
            self._record("file.repair", Action.FILE_REPAIR, Outcome.SUCCESS if ok else Outcome.FAILURE,
                         subject, context, file_id=row.id,
                         severity=Severity.INFO if ok else Severity.CRITICAL,
                         details={"chunk_count": len(manifest["chunks"]), "chunks_repaired": len(repaired),
                                  "chunks_unrepairable": len(unrepairable), "ok": ok})
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            keys.destroy()
        return {"file_id": row.id, "ok": not unrepairable, "repaired_chunks": repaired,
                "unrepairable_chunks": unrepairable}

    # ------------------------------------------------------------------ #
    # statistics (dashboard)
    # ------------------------------------------------------------------ #
    def stats(self, db: DbSession, owner_id: str | None = None) -> dict[str, Any]:
        """Real counts from the metadata DB. ``owner_id`` scopes to one user."""
        f = select(File.status, func.count(), func.coalesce(func.sum(File.size_bytes), 0),
                   func.coalesce(func.sum(File.chunk_count), 0)).group_by(File.status)
        if owner_id is not None:
            f = f.where(File.owner_id == owner_id)
        by_status = {s: {"files": 0, "bytes": 0, "chunks": 0} for s in (
            FileStatus.PENDING, FileStatus.UPLOADING, FileStatus.COMMITTED, FileStatus.FAILED,
            FileStatus.DELETING, FileStatus.DELETED)}
        for status, n, size, chunks in db.execute(f).all():
            by_status[status] = {"files": int(n), "bytes": int(size), "chunks": int(chunks)}
        rep = (select(ChunkReplica.provider, ChunkReplica.status, func.count(),
                      func.coalesce(func.sum(Chunk.ciphertext_size), 0))
               .join(Chunk, Chunk.id == ChunkReplica.chunk_id).join(File, File.id == Chunk.file_id)
               .where(File.status == FileStatus.COMMITTED)
               .group_by(ChunkReplica.provider, ChunkReplica.status))
        if owner_id is not None:
            rep = rep.where(File.owner_id == owner_id)
        providers: dict[str, dict[str, Any]] = {
            n: {"replicas": 0, "bytes": 0, "by_status": {}} for n in self._orch.provider_names}
        for provider, status, n, size in db.execute(rep).all():
            d = providers.setdefault(provider, {"replicas": 0, "bytes": 0, "by_status": {}})
            d["by_status"][status] = int(n)
            if status == ReplicaStatus.STORED:
                d["replicas"] += int(n)
                d["bytes"] += int(size)
        c = by_status[FileStatus.COMMITTED]
        return {"files": c["files"], "bytes": c["bytes"], "chunks": c["chunks"],
                "files_by_status": {k: v["files"] for k, v in by_status.items()},
                "distribution": providers}

    # ------------------------------------------------------------------ #
    # KMS rotation support
    # ------------------------------------------------------------------ #
    def rewrap_all(self, db: DbSession, kms: Any) -> tuple[int, int]:
        """Re-wrap every live wrapped DEK under the active KEK version (no
        chunk is re-encrypted). Returns (rewrapped, failed)."""
        from app.cryptoengine import dek_context
        ok = failed = 0
        rows = db.execute(select(File).where(File.wrapped_dek.is_not(None))).scalars().all()
        for row in rows:
            try:
                dk = kms.rewrap_data_key(row.wrapped_dek, context=dek_context(row.id, row.owner_id))
            except KmsError:
                failed += 1
                continue
            row.wrapped_dek, row.kek_id, row.kek_version = dk.wrapped, dk.key_id, dk.key_version
            ok += 1
        db.commit()
        return ok, failed

    # ------------------------------------------------------------------ #
    # recovery / maintenance
    # ------------------------------------------------------------------ #
    def recover(self, db: DbSession) -> dict[str, int]:
        """Crash recovery + housekeeping (idempotent):
          * PENDING/UPLOADING older than ``stale_upload_minutes``: delete every
            recorded chunk id from EVERY provider (the store call may have been
            in flight), shred key material, mark FAILED("interrupted");
          * DELETING older than the same age: finish the delete + shred;
          * replicas recorded as leftovers of failed/deleted files: retry delete.
        """
        now = self._now()
        cutoff = now - timedelta(minutes=self.stale_upload_minutes)
        out = {"uploads_recovered": 0, "deletes_finished": 0, "leftovers_removed": 0}
        stale = db.execute(select(File).where(File.status.in_([FileStatus.PENDING, FileStatus.UPLOADING]),
                                              File.created_at < cutoff)).scalars().all()
        for row in stale:
            claimed = db.execute(update(File).where(File.id == row.id, File.status == row.status)
                                 .values(status=FileStatus.FAILED, failure_reason="interrupted",
                                         wrapped_dek=None, enc_metadata=None, manifest_json=None,
                                         manifest_mac=None)).rowcount
            db.commit()
            if claimed != 1:
                continue
            names = self._orch.provider_names
            for ch in db.execute(select(Chunk).where(Chunk.file_id == row.id)).scalars().all():
                res = self._orch.delete_chunk(ch.id, names)
                for p in res.deleted:
                    self._set_replica(db, ch.id, p, ReplicaStatus.DELETED)
                for fl in res.failed:
                    self._set_replica(db, ch.id, fl.provider, LEFTOVER)
            db.commit()
            self._record("file.upload", Action.FILE_CREATE, Outcome.ERROR, None, None, file_id=row.id,
                         reason="interrupted", severity=Severity.WARNING,
                         details={"status": FileStatus.FAILED})
            out["uploads_recovered"] += 1
        deleting = db.execute(select(File.id).where(File.status == FileStatus.DELETING,
                                                    File.created_at < cutoff)).scalars().all()
        for fid in deleting:
            self._purge(db, fid, None, None)
            out["deletes_finished"] += 1
        leftovers = db.execute(
            select(ChunkReplica).join(Chunk, Chunk.id == ChunkReplica.chunk_id).join(File, File.id == Chunk.file_id)
            .where(ChunkReplica.status == LEFTOVER,
                   File.status.in_([FileStatus.FAILED, FileStatus.DELETED]))).scalars().all()
        for rep in leftovers:
            res = self._orch.delete_chunk(rep.chunk_id, [rep.provider])
            if res.deleted:
                rep.status = ReplicaStatus.DELETED
                out["leftovers_removed"] += 1
        db.commit()
        return out
