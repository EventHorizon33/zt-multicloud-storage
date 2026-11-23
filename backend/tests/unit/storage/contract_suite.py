"""Provider contract test suite, shared by the unit tests (MemoryProvider)
and the emulator integration tests (S3 / Azure / GCS adapters).

Subclasses provide a ``provider`` fixture. Every test works under a unique
key namespace so the suite can run against shared emulator buckets."""
from __future__ import annotations

import os
import uuid

import pytest

from app.contracts import HealthStatus, ObjectInfo, ObjectNotFound, StorageError, StorageProvider
from app.storage import InvalidObjectKey

INVALID_KEYS = [
    "",
    "../etc/passwd",
    "a/../b",
    "..",
    "/abs/key",
    "back\\slash",
    "nul\x00byte",
    "new\nline",
    "tab\tkey",
    "del\x7fchar",
    "k" * 257,
]


class ProviderContract:
    @pytest.fixture
    def ns(self) -> str:
        return f"contract-{uuid.uuid4().hex[:12]}/"

    def test_identity(self, provider: StorageProvider):
        assert isinstance(provider.name, str) and provider.name
        assert provider.kind in ("s3", "azure", "gcs", "memory")

    def test_put_get_roundtrip_binary(self, provider, ns):
        data = bytes(range(256)) * 64 + os.urandom(70_000)
        info = provider.put(ns + "bin", data)
        assert isinstance(info, ObjectInfo)
        assert info.key == ns + "bin" and info.size == len(data)
        assert provider.get(ns + "bin") == data

    def test_empty_object(self, provider, ns):
        provider.put(ns + "empty", b"")
        assert provider.get(ns + "empty") == b""
        assert provider.stat(ns + "empty").size == 0

    def test_overwrite_replaces_content(self, provider, ns):
        provider.put(ns + "k", b"first version")
        provider.put(ns + "k", b"second")
        assert provider.get(ns + "k") == b"second"
        assert provider.stat(ns + "k").size == 6

    def test_exists(self, provider, ns):
        assert provider.exists(ns + "x") is False
        provider.put(ns + "x", b"1")
        assert provider.exists(ns + "x") is True

    def test_stat_size_and_metadata(self, provider, ns):
        provider.put(ns + "s", b"abcdef", metadata={"fmt": "v1"})
        info = provider.stat(ns + "s")
        assert info.size == 6
        assert info.key == ns + "s"
        assert dict(info.metadata).get("fmt") == "v1"

    def test_delete_is_idempotent(self, provider, ns):
        provider.put(ns + "d", b"data")
        provider.delete(ns + "d")
        assert provider.exists(ns + "d") is False
        provider.delete(ns + "d")              # again: no error
        provider.delete(ns + "never-existed")  # never existed: no error

    def test_get_missing_raises_object_not_found(self, provider, ns):
        with pytest.raises(ObjectNotFound) as ei:
            provider.get(ns + "missing")
        assert ei.value.retryable is False
        assert ei.value.provider == provider.name

    def test_stat_missing_raises_object_not_found(self, provider, ns):
        with pytest.raises(ObjectNotFound):
            provider.stat(ns + "missing")

    def test_list_keys_prefix(self, provider, ns):
        for k in ("a/1", "a/2", "b/1"):
            provider.put(ns + k, b"x")
        assert sorted(provider.list_keys(ns + "a/")) == [ns + "a/1", ns + "a/2"]
        assert sorted(provider.list_keys(ns)) == [ns + "a/1", ns + "a/2", ns + "b/1"]
        assert list(provider.list_keys(ns + "zzz/")) == []

    def test_list_keys_paginates(self, provider, ns):
        keys = [f"{ns}p/{i:04d}" for i in range(25)]
        for k in keys:
            provider.put(k, b"")
        assert sorted(provider.list_keys(ns + "p/")) == keys

    @pytest.mark.parametrize("bad", INVALID_KEYS, ids=lambda k: repr(k)[:20])
    def test_invalid_keys_rejected(self, provider, bad):
        for call in (lambda: provider.put(bad, b"x"), lambda: provider.get(bad),
                     lambda: provider.delete(bad), lambda: provider.exists(bad),
                     lambda: provider.stat(bad)):
            with pytest.raises(InvalidObjectKey) as ei:
                call()
            assert isinstance(ei.value, StorageError) and not ei.value.retryable
            if len(bad) > 3:
                assert bad not in str(ei.value)  # never echo the key

    def test_invalid_prefix_rejected(self, provider):
        with pytest.raises(InvalidObjectKey):
            provider.list_keys("../")

    def test_non_bytes_rejected(self, provider, ns):
        with pytest.raises(StorageError):
            provider.put(ns + "s", "text is not ciphertext")  # type: ignore[arg-type]

    def test_health(self, provider):
        st = provider.health()
        assert isinstance(st, HealthStatus)
        assert st.provider == provider.name
        assert st.healthy is True and st.error is None
        assert st.latency_ms is not None and st.latency_ms >= 0
