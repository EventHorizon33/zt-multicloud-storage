"""In-memory provider. FOR UNIT TESTS ONLY.

It keeps every object in a process-local dict: nothing is durable, nothing is
shared between processes, and there is no independent failure domain. It is
never a substitute for a cloud provider and ``build_providers`` refuses to
create one unless ``settings.env == "test"``.
"""
from __future__ import annotations

import hashlib
import threading
import time
from typing import Iterator, Mapping

from app.contracts import HealthStatus, ObjectInfo, ObjectNotFound, StorageProvider

from ._common import require_bytes, utcnow, validate_key, validate_metadata, validate_prefix


class MemoryProvider(StorageProvider):
    """Thread-safe dict-backed ``StorageProvider`` used by unit tests.

    Security property: none beyond key validation. Test double only."""

    kind = "memory"

    def __init__(self, name: str = "memory") -> None:
        self.name = name
        self._lock = threading.RLock()
        self._objects: dict[str, tuple[bytes, dict[str, str], object]] = {}

    def ensure_bucket(self) -> None:
        """No-op: there is no bucket to create."""

    def put(self, key: str, data: bytes, metadata: Mapping[str, str] | None = None) -> ObjectInfo:
        validate_key(key)
        blob = require_bytes(data)
        meta = validate_metadata(metadata)
        now = utcnow()
        with self._lock:
            self._objects[key] = (blob, meta, now)
        return ObjectInfo(key=key, size=len(blob), etag=hashlib.md5(blob, usedforsecurity=False).hexdigest(),
                          last_modified=now, metadata=dict(meta))

    def get(self, key: str) -> bytes:
        validate_key(key)
        with self._lock:
            entry = self._objects.get(key)
        if entry is None:
            raise ObjectNotFound("memory get failed: object not found", provider=self.name)
        return entry[0]

    def delete(self, key: str) -> None:
        validate_key(key)
        with self._lock:
            self._objects.pop(key, None)

    def exists(self, key: str) -> bool:
        validate_key(key)
        with self._lock:
            return key in self._objects

    def stat(self, key: str) -> ObjectInfo:
        validate_key(key)
        with self._lock:
            entry = self._objects.get(key)
        if entry is None:
            raise ObjectNotFound("memory stat failed: object not found", provider=self.name)
        blob, meta, modified = entry
        return ObjectInfo(key=key, size=len(blob), etag=hashlib.md5(blob, usedforsecurity=False).hexdigest(),
                          last_modified=modified, metadata=dict(meta))  # type: ignore[arg-type]

    def list_keys(self, prefix: str = "") -> Iterator[str]:
        validate_prefix(prefix)
        with self._lock:
            keys = sorted(k for k in self._objects if k.startswith(prefix))
        return iter(keys)

    def health(self) -> HealthStatus:
        start = time.perf_counter()
        with self._lock:
            len(self._objects)
        return HealthStatus(provider=self.name, healthy=True,
                            latency_ms=(time.perf_counter() - start) * 1000.0, checked_at=utcnow())

    # test helper ---------------------------------------------------------- #
    def object_count(self) -> int:
        with self._lock:
            return len(self._objects)
