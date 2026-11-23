"""Cross-module contracts.

Every subsystem (auth, policy, kms, cryptoengine, storage, audit) depends on the
types in this file and NOT on each other's concrete classes. Concrete
implementations are wired together in ``app/container.py``.

Rules:
  * Do not change a signature here without updating docs/CONTRACTS.md.
  * Nothing in this file performs I/O.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Iterator, Mapping, Protocol, runtime_checkable


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
class Outcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"   # operation attempted and failed (bad password, integrity failure)
    DENIED = "denied"     # policy decision refused the operation
    ERROR = "error"       # infrastructure fault (provider down, timeout)


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@runtime_checkable
class AuditSink(Protocol):
    """What every other module is allowed to know about the audit subsystem.

    ``actor_id`` is the raw internal user id; the audit subsystem converts it to
    a pseudonym before anything is persisted. ``details`` passes through the
    privacy filter: unknown keys are rejected/redacted, so callers must only
    pass non-sensitive, allow-listed fields (see app/audit/privacy.py).
    ``source_ip`` is generalised (e.g. /24) before storage.

    record() must never raise into the caller for privacy-filter reasons
    (it redacts instead) but MUST raise if the event could not be durably
    written: an operation that cannot be audited must not proceed.
    """

    def record(
        self,
        *,
        event_type: str,          # dotted, e.g. "auth.login", "file.download", "authz.decision"
        action: str,              # policy action or verb, e.g. "file:read"
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
    ) -> Any: ...


# --------------------------------------------------------------------------- #
# Key management
# --------------------------------------------------------------------------- #
class KeyPurpose(str, Enum):
    """Distinct purposes use distinct root keys (key separation)."""
    FILE_DEK_WRAP = "file-dek-wrap"        # KEK that wraps per-file data keys
    SECRET_ENCRYPTION = "secret-encryption"  # small secrets at rest (TOTP seeds)
    TOKEN_SIGNING = "token-signing"        # Ed25519, access tokens
    AUDIT_SIGNING = "audit-signing"        # Ed25519, audit checkpoints
    AUDIT_PSEUDONYM = "audit-pseudonym"    # HMAC key for actor pseudonyms
    LOOKUP_HMAC = "lookup-hmac"            # HMAC key for refresh-token / ip hashing


@dataclass(frozen=True)
class DataKey:
    plaintext: bytes      # 32 bytes. Never persist, never log.
    wrapped: bytes        # opaque blob safe to store in the metadata DB
    key_id: str           # KEK identifier
    key_version: int      # KEK version used for wrapping


@dataclass(frozen=True)
class KeyInfo:
    purpose: str
    key_id: str
    version: int
    algorithm: str
    created_at: datetime
    state: str            # "active" | "decrypt-only" | "retired"


@dataclass(frozen=True)
class Signature:
    key_id: str
    version: int
    signature: bytes


class KeyManagementService(ABC):
    """KMS abstraction. Key material never leaves an implementation except as
    the ``DataKey.plaintext`` returned from generate/unwrap and the HMAC result
    of ``mac``. ``context`` is bound as AEAD associated data: unwrapping with a
    different context MUST fail."""

    @abstractmethod
    def generate_data_key(self, *, context: Mapping[str, str]) -> DataKey: ...

    @abstractmethod
    def unwrap_data_key(self, wrapped: bytes, *, context: Mapping[str, str]) -> bytes: ...

    @abstractmethod
    def rewrap_data_key(self, wrapped: bytes, *, context: Mapping[str, str]) -> DataKey:
        """Re-wrap under the current active KEK version. ``plaintext`` of the
        returned DataKey MUST be empty bytes (callers of rewrap never need it)."""

    @abstractmethod
    def wrapped_key_version(self, wrapped: bytes) -> tuple[str, int]:
        """(key_id, version) a wrapped blob was produced with, without unwrapping."""

    @abstractmethod
    def encrypt(self, plaintext: bytes, *, context: Mapping[str, str]) -> bytes:
        """Encrypt a small secret under the SECRET_ENCRYPTION key."""

    @abstractmethod
    def decrypt(self, ciphertext: bytes, *, context: Mapping[str, str]) -> bytes: ...

    @abstractmethod
    def sign(self, message: bytes, *, purpose: KeyPurpose) -> Signature: ...

    @abstractmethod
    def verify(self, message: bytes, signature: bytes, *, purpose: KeyPurpose,
               key_id: str, version: int) -> bool: ...

    @abstractmethod
    def public_key_pem(self, *, purpose: KeyPurpose, version: int | None = None) -> bytes: ...

    @abstractmethod
    def mac(self, message: bytes, *, purpose: KeyPurpose) -> bytes:
        """HMAC-SHA256 under the purpose's key (AUDIT_PSEUDONYM / LOOKUP_HMAC)."""

    def mac_all_versions(self, message: bytes, *, purpose: KeyPurpose) -> list[bytes]:
        """HMAC-SHA256 under EVERY retained version of an HMAC purpose, newest
        first. Used to match audit pseudonyms written before a key rotation
        (finding M3). Default: only the active version."""
        return [self.mac(message, purpose=purpose)]

    @abstractmethod
    def rotate(self, purpose: KeyPurpose) -> KeyInfo:
        """Create a new active version; previous versions stay usable for
        decrypt/verify only."""

    @abstractmethod
    def list_keys(self) -> list[KeyInfo]:
        """Metadata only. Never returns key material."""


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #
class StorageError(Exception):
    """Base. ``retryable`` tells the orchestrator whether to back off and retry."""
    retryable = False

    def __init__(self, message: str, *, provider: str | None = None):
        super().__init__(message)
        self.provider = provider


class ObjectNotFound(StorageError):
    retryable = False


class ProviderUnavailable(StorageError):
    retryable = True


class ProviderTimeout(StorageError):
    retryable = True


class ProviderAuthError(StorageError):
    retryable = False


@dataclass(frozen=True)
class ObjectInfo:
    key: str
    size: int
    etag: str | None = None
    last_modified: datetime | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class HealthStatus:
    provider: str
    healthy: bool
    latency_ms: float | None
    checked_at: datetime
    error: str | None = None      # sanitised: no credentials, no endpoints with secrets


class StorageProvider(ABC):
    """One bucket/container at one cloud provider. Implementations translate
    provider SDK exceptions into the StorageError hierarchy above and must
    never include credentials in exception messages.

    Only opaque object keys and ciphertext ever reach a provider. Providers
    receive no key material and no user-identifying metadata."""

    name: str   # configured instance name, e.g. "aws-s3"
    kind: str   # "s3" | "azure" | "gcs" | "memory"

    @abstractmethod
    def put(self, key: str, data: bytes, metadata: Mapping[str, str] | None = None) -> ObjectInfo: ...

    @abstractmethod
    def get(self, key: str) -> bytes: ...

    @abstractmethod
    def delete(self, key: str) -> None:
        """Idempotent: deleting a missing object is not an error."""

    @abstractmethod
    def exists(self, key: str) -> bool: ...

    @abstractmethod
    def stat(self, key: str) -> ObjectInfo: ...

    @abstractmethod
    def list_keys(self, prefix: str = "") -> Iterator[str]: ...

    @abstractmethod
    def health(self) -> HealthStatus:
        """Cheap probe. Must not raise; returns healthy=False instead."""


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #
class Role(str, Enum):
    USER = "user"
    AUDITOR = "auditor"
    ADMIN = "admin"


class Classification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @property
    def rank(self) -> int:
        return ["public", "internal", "confidential", "restricted"].index(self.value)


class Action(str, Enum):
    FILE_CREATE = "file:create"
    FILE_LIST = "file:list"
    FILE_READ_METADATA = "file:read-metadata"
    FILE_READ = "file:read"              # download + decrypt
    FILE_DELETE = "file:delete"
    FILE_SHARE = "file:share"
    FILE_VERIFY = "file:verify"          # integrity scrub (no plaintext leaves)
    FILE_REPAIR = "file:repair"
    AUDIT_READ_OWN = "audit:read-own"
    AUDIT_READ_ALL = "audit:read-all"
    AUDIT_VERIFY = "audit:verify"
    AUDIT_CHECKPOINT = "audit:checkpoint"
    AUDIT_RETENTION = "audit:retention"
    USER_LIST = "user:list"
    USER_MANAGE = "user:manage"          # role, disable, allow-list, revoke sessions
    POLICY_READ = "policy:read"
    POLICY_WRITE = "policy:write"
    KMS_READ = "kms:read"
    KMS_ROTATE = "kms:rotate"
    STORAGE_READ = "storage:read"        # provider health / distribution
    STORAGE_ADMIN = "storage:admin"      # fault injection (demo), repair sweeps
    DASHBOARD_READ = "dashboard:read"
    SECURITY_READ = "security:read"


@dataclass(frozen=True)
class Subject:
    user_id: str
    role: Role
    clearance: Classification
    session_id: str
    mfa_enrolled: bool
    mfa_verified: bool               # this session has passed a second factor
    mfa_age_seconds: float | None    # since last second-factor verification
    session_age_seconds: float
    allowed_cidrs: tuple[str, ...]   # empty = no network restriction configured
    is_active: bool = True


@dataclass(frozen=True)
class Resource:
    type: str                        # "file" | "user" | "audit" | "policy" | "kms" | "storage" | "system"
    id: str | None = None
    owner_id: str | None = None
    classification: Classification | None = None
    shared_with_subject: bool = False
    status: str | None = None


@dataclass(frozen=True)
class RequestContext:
    request_id: str
    source_ip: str | None
    now: datetime
    # behavioural signals supplied by app/detection (None = not evaluated)
    recent_download_count: int | None = None
    recent_download_bytes: int | None = None
    download_blocked: bool = False


@dataclass(frozen=True)
class Decision:
    allow: bool
    reasons: tuple[str, ...]         # machine-readable codes, e.g. "not-owner", "mfa-required"
    matched_policies: tuple[str, ...]
    obligations: tuple[str, ...] = ()  # e.g. "step-up-mfa"
