"""Value types returned by the audit subsystem."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

from app.audit.chain import CHECKPOINT_VERSION, canonical_json

ANCHOR_PREFIX = "anchors/audit/"
CHECKPOINT_KINDS = ("periodic", "manual", "retention")

# Findings that do not make a verification fail on their own.
INFORMATIONAL_FINDINGS = frozenset({"anchor-missing", "anchor-unavailable"})


def anchor_prefix(log_id: str) -> str:
    """Namespace of one audit log's anchors (ADR-0006 amendment, finding F4):
    ``anchors/audit/<log_id>/``. ``log_id`` is 16 lowercase hex characters."""
    return f"{ANCHOR_PREFIX}{log_id}/"


def anchor_key(kind: str, seq: int, log_id: str) -> str:
    """Object key of a checkpoint's anchor copy, inside the log's namespace.
    Periodic and manual checkpoints share ``checkpoint-<seq>``; a retention
    checkpoint (which can exist at a seq that already has a periodic one)
    uses ``retention-<seq>`` so the two never overwrite each other."""
    stem = "retention" if kind == "retention" else "checkpoint"
    return f"{anchor_prefix(log_id)}{stem}-{seq:012d}.json"


@dataclass(frozen=True)
class AuditContext:
    """Who is performing an audited housekeeping operation (checkpoint,
    verify, retention). Passed by the API layer so the audit subsystem can
    record the operation itself as an audit event."""
    actor_id: str | None = None
    actor_role: str | None = None
    request_id: str | None = None
    source_ip: str | None = None


@dataclass(frozen=True)
class AuditRecord:
    """What ``record()`` returns: the position and hash of the stored event."""
    seq: int
    id: str
    ts: str
    hash: str
    prev_hash: str


@dataclass(frozen=True)
class Checkpoint:
    id: str
    seq: int
    head_hash: str
    ts: str
    kind: str
    key_id: str
    key_version: int
    signature: str                  # hex
    event_count: int
    first_seq: int
    anchors: Mapping[str, bool] = field(default_factory=dict)

    def payload(self) -> str:
        """The exact text that is signed."""
        return canonical_json({
            "v": CHECKPOINT_VERSION, "seq": self.seq, "head_hash": self.head_hash,
            "ts": self.ts, "event_count": self.event_count,
            "first_seq": self.first_seq, "kind": self.kind,
        })

    def document(self) -> bytes:
        """The anchor document written to storage providers."""
        return canonical_json({
            "v": CHECKPOINT_VERSION, "alg": "Ed25519", "payload": self.payload(),
            "signature": self.signature, "key_id": self.key_id,
            "key_version": self.key_version,
        }).encode("ascii")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["anchors"] = dict(self.anchors)
        return d

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "Checkpoint":
        try:
            anchors = json.loads(row["anchors"] or "{}")
            if not isinstance(anchors, dict):
                anchors = {}
        except (TypeError, ValueError):
            anchors = {}
        return cls(
            id=row["id"], seq=row["seq"], head_hash=row["head_hash"], ts=row["ts"],
            kind=row["kind"], key_id=row["key_id"], key_version=row["key_version"],
            signature=row["signature"], event_count=row["event_count"],
            first_seq=row["first_seq"],
            anchors={str(k): bool(v) for k, v in anchors.items()},
        )


@dataclass(frozen=True)
class Finding:
    type: str
    seq: int | None
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "seq": self.seq, "detail": self.detail}


@dataclass
class VerificationReport:
    ok: bool
    events_checked: int
    first_seq: int | None
    last_seq: int | None
    head_hash: str | None
    checkpoints_checked: int
    anchors_checked: int
    findings: list[Finding] = field(default_factory=list)
    findings_truncated: bool = False     # only ever True when max_findings was given
    duration_ms: float = 0.0

    def finding_types(self) -> set[str]:
        return {f.type for f in self.findings}

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok, "events_checked": self.events_checked,
            "first_seq": self.first_seq, "last_seq": self.last_seq,
            "head_hash": self.head_hash,
            "checkpoints_checked": self.checkpoints_checked,
            "anchors_checked": self.anchors_checked,
            "findings": [f.to_dict() for f in self.findings],
            "findings_truncated": self.findings_truncated,
            "duration_ms": self.duration_ms,
        }


@dataclass(frozen=True)
class RetentionResult:
    deleted: int
    kept: int
    new_first_seq: int | None       # first retained seq (None: nothing retained and nothing ever pruned)
    checkpoint_seq: int | None      # seq of the retention checkpoint (None: nothing deleted)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
