"""Metadata database models (users, sessions, files, manifests, chunk index).

The audit log lives in a SEPARATE database with its own models
(app/audit/models.py, ADR-0006). No key material is stored here except
*wrapped* data keys, which are useless without the KMS.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, DateTime, ForeignKey, Index, Integer, LargeBinary,
                        String, Text, UniqueConstraint, func)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))          # argon2id encoded
    role: Mapped[str] = mapped_column(String(16), default="user")    # contracts.Role
    clearance: Mapped[str] = mapped_column(String(16), default="confidential")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)  # KMS-encrypted TOTP seed
    mfa_last_counter: Mapped[int | None] = mapped_column(Integer, nullable=True)      # TOTP replay guard
    allowed_cidrs: Mapped[list] = mapped_column(JSON, default=list)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Case-insensitive uniqueness, enforced by the database (not only by the
    # service's lookup), so concurrent "Alice"/"alice" registrations cannot
    # both succeed. Usernames are also stored lowercase by app/auth.
    __table_args__ = (Index("uq_users_username_lower", func.lower(username), unique=True),)


class Session(Base):
    """Server-side session. Access tokens carry the session id and are checked
    against this row on EVERY request, so revocation is immediate."""
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))   # absolute lifetime
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoke_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mfa_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ip_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)   # HMAC(ip), not the ip
    user: Mapped[User] = relationship()


class MfaFactorState(Base):
    """MFA enrolment bookkeeping (ADR-0010), kept out of ``users`` so existing
    databases need no column migration (``create_all`` adds the table).

    * ``ever_enabled``: the account has had an active factor at least once, so
      the trust-on-first-use window no longer applies (also after a disable or
      an admin reset).
    * ``pending_*``: an enrolment that was started and not yet activated, and
      on what basis it was allowed (``tofu`` | ``bootstrap`` | ``admin-code`` |
      ``rotation``). For a first factor the pending seed lives in
      ``users.mfa_secret_enc`` (with ``mfa_enabled`` false); for a replacement
      of an existing factor it lives in ``pending_secret_enc`` so the current
      factor keeps working until the new one is proven."""
    __tablename__ = "mfa_factor_state"
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)
    ever_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    pending_basis: Mapped[str | None] = mapped_column(String(16), nullable=True)
    pending_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    pending_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)  # KMS-encrypted


class MfaEnrollmentCode(Base):
    """Admin-issued, single-use, time-limited permission to enrol a factor
    outside the trust-on-first-use window. Only an HMAC of the code is stored."""
    __tablename__ = "mfa_enrollment_codes"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    code_hmac: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    issued_by: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RefreshToken(Base):
    """Opaque, single-use, rotated. Only an HMAC of the token is stored. Reuse
    of an already-used token revokes the whole session (theft detection)."""
    __tablename__ = "refresh_tokens"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class FileStatus:
    PENDING = "pending"        # row created, nothing stored yet
    UPLOADING = "uploading"    # chunks being written to providers
    COMMITTED = "committed"    # all chunks at >= min replicas, manifest sealed
    FAILED = "failed"          # upload aborted; chunks cleaned up (or queued for cleanup)
    DELETING = "deleting"      # delete in progress
    DELETED = "deleted"        # chunks removed, wrapped key destroyed (crypto-shredded)


class File(Base):
    __tablename__ = "files"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), default=FileStatus.PENDING, index=True)
    classification: Mapped[str] = mapped_column(String(16), default="internal")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    chunk_size: Mapped[int] = mapped_column(Integer)
    chunk_count: Mapped[int] = mapped_column(Integer, default=0)
    # --- cryptographic material references (never plaintext keys) ---
    wrapped_dek: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    kek_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    kek_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # filename / mime / plaintext sha256, AES-GCM under a key derived from the DEK
    enc_metadata: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # canonical JSON manifest + HMAC under a key derived from the DEK
    manifest_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    manifest_mac: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    committed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    chunks: Mapped[list["Chunk"]] = relationship(back_populates="file", order_by="Chunk.index",
                                                 cascade="all, delete-orphan")


class Chunk(Base):
    """Queryable projection of the manifest for the UI / ops. The MAC-protected
    manifest on ``File`` is the source of truth during reconstruction."""
    __tablename__ = "chunks"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)   # opaque random object key
    file_id: Mapped[str] = mapped_column(ForeignKey("files.id"), index=True)
    index: Mapped[int] = mapped_column(Integer)
    ciphertext_size: Mapped[int] = mapped_column(Integer)
    ciphertext_sha256: Mapped[str] = mapped_column(String(64))
    file: Mapped[File] = relationship(back_populates="chunks")
    replicas: Mapped[list["ChunkReplica"]] = relationship(back_populates="chunk",
                                                          cascade="all, delete-orphan")
    __table_args__ = (UniqueConstraint("file_id", "index", name="uq_chunk_file_index"),)


class ReplicaStatus:
    PENDING = "pending"
    STORED = "stored"
    FAILED = "failed"
    MISSING = "missing"     # detected absent during retrieval/scrub
    CORRUPT = "corrupt"     # detected hash mismatch during retrieval/scrub
    DELETED = "deleted"


class ChunkReplica(Base):
    __tablename__ = "chunk_replicas"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    chunk_id: Mapped[str] = mapped_column(ForeignKey("chunks.id"), index=True)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(16), default=ReplicaStatus.PENDING)
    stored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    chunk: Mapped[Chunk] = relationship(back_populates="replicas")
    __table_args__ = (UniqueConstraint("chunk_id", "provider", name="uq_replica_chunk_provider"),)


class FileShare(Base):
    __tablename__ = "file_shares"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    file_id: Mapped[str] = mapped_column(ForeignKey("files.id"), index=True)
    grantee_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    granted_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    __table_args__ = (Index("ix_share_file_grantee", "file_id", "grantee_id"),)


class PolicySetting(Base):
    """Runtime-adjustable policy parameters. Every change is audited."""
    __tablename__ = "policy_settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(32), nullable=True)


class DownloadRecord(Base):
    """Sliding-window input for bulk-export detection (pruned continuously)."""
    __tablename__ = "download_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(32), index=True)
    file_id: Mapped[str] = mapped_column(String(32))
    size_bytes: Mapped[int] = mapped_column(Integer)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class DownloadBlock(Base):
    __tablename__ = "download_blocks"
    user_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    blocked_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(String(64))
