"""Google Cloud Storage adapter (google-cloud-storage).

Security properties:
  * real GCS uses Application Default Credentials (workload identity / service
    account supplied by the environment); nothing is hardcoded. Anonymous
    credentials are used ONLY when an emulator endpoint is configured;
  * exception messages are fixed templates plus exception class / HTTP status;
  * object keys are validated before any request;
  * SDK retries are disabled (``retry=None`` on every call): the orchestrator
    owns retry/backoff.
"""
from __future__ import annotations

import time
from typing import Any, Iterator, Mapping

import requests
from google.api_core import exceptions as gexc
from google.auth import exceptions as gauth_exc
from google.auth.credentials import AnonymousCredentials
from google.cloud import storage as gcs_storage

from app.contracts import (
    HealthStatus,
    ObjectInfo,
    ObjectNotFound,
    ProviderAuthError,
    ProviderTimeout,
    ProviderUnavailable,
    StorageError,
    StorageProvider,
)

from ._common import (
    StorageConfigError,
    error_summary,
    require_bytes,
    safe_code,
    utcnow,
    validate_key,
    validate_metadata,
    validate_prefix,
)

try:  # raised by the media layer on checksum mismatch / bad responses
    from google.resumable_media import common as _media_common
    _MEDIA_ERRORS: tuple[type[BaseException], ...] = (
        _media_common.InvalidResponse, _media_common.DataCorruption)
except Exception:  # pragma: no cover - layout differs between SDK versions
    _MEDIA_ERRORS = ()


class GCSProvider(StorageProvider):
    """One GCS bucket."""

    kind = "gcs"

    def __init__(
        self,
        *,
        bucket: str,
        name: str = "gcs",
        project: str | None = None,
        endpoint_url: str | None = None,
        timeout_seconds: float = 10.0,
        connect_timeout_seconds: float | None = None,
    ) -> None:
        if not bucket:
            raise StorageConfigError("gcs provider requires a bucket name (ZT_GCS_BUCKET)", provider=name)
        self.name = name
        self.bucket_name = bucket
        self.is_emulated = bool(endpoint_url)
        self._timeout = (connect_timeout_seconds or min(timeout_seconds, 5.0), timeout_seconds)
        try:
            if endpoint_url:
                # Emulator only: no credentials exist, so none are sent.
                self._client = gcs_storage.Client(
                    project=project or "zt-local",
                    credentials=AnonymousCredentials(),
                    client_options={"api_endpoint": endpoint_url},
                )
            else:
                self._client = gcs_storage.Client(project=project)
        except gauth_exc.DefaultCredentialsError:
            raise ProviderAuthError(
                "gcs client could not be created: no Application Default Credentials found",
                provider=name) from None
        except Exception as exc:
            raise StorageConfigError(
                f"gcs client could not be created ({safe_code(type(exc).__name__)})", provider=name) from None
        self._bucket = self._client.bucket(bucket)

    @classmethod
    def from_settings(cls, settings: Any, name: str = "gcs") -> "GCSProvider":
        return cls(
            name=name,
            bucket=settings.gcs_bucket,
            project=settings.gcs_project,
            endpoint_url=settings.gcs_endpoint_url,
            timeout_seconds=settings.storage_timeout_seconds,
        )

    # -- error translation -------------------------------------------------- #
    def _translate(self, op: str, exc: BaseException) -> StorageError:
        p = self.name
        cls_name = safe_code(type(exc).__name__)
        if isinstance(exc, StorageError):
            return exc
        if isinstance(exc, gexc.GoogleAPICallError):
            status = getattr(exc, "code", None)
            status = int(status) if isinstance(status, int) else getattr(status, "value", status)
            detail = f"{cls_name}, status={status}"
            if isinstance(exc, gexc.NotFound):
                return ObjectNotFound(f"gcs {op} failed: object not found", provider=p)
            if isinstance(exc, (gexc.Unauthorized, gexc.Forbidden)):
                return ProviderAuthError(f"gcs {op} failed: access denied ({detail})", provider=p)
            if isinstance(exc, (gexc.GatewayTimeout, gexc.DeadlineExceeded)) or status == 408:
                return ProviderTimeout(f"gcs {op} failed: request timed out ({detail})", provider=p)
            if isinstance(exc, (gexc.TooManyRequests, gexc.ServerError)):
                return ProviderUnavailable(f"gcs {op} failed: service unavailable ({detail})", provider=p)
            return StorageError(f"gcs {op} failed: service error ({detail})", provider=p)
        if isinstance(exc, gexc.RetryError):
            return ProviderTimeout(f"gcs {op} failed: timed out ({cls_name})", provider=p)
        if isinstance(exc, (gauth_exc.DefaultCredentialsError, gauth_exc.RefreshError)):
            return ProviderAuthError(f"gcs {op} failed: no usable credentials ({cls_name})", provider=p)
        if isinstance(exc, gauth_exc.TransportError):
            return ProviderUnavailable(f"gcs {op} failed: connection failed ({cls_name})", provider=p)
        if isinstance(exc, requests.exceptions.Timeout):
            return ProviderTimeout(f"gcs {op} failed: timed out ({cls_name})", provider=p)
        if isinstance(exc, requests.exceptions.RequestException):
            return ProviderUnavailable(f"gcs {op} failed: connection failed ({cls_name})", provider=p)
        if _MEDIA_ERRORS and isinstance(exc, _MEDIA_ERRORS):
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status == 404:
                return ObjectNotFound(f"gcs {op} failed: object not found", provider=p)
            if status in (401, 403):
                return ProviderAuthError(f"gcs {op} failed: access denied (status={status})", provider=p)
            if isinstance(status, int) and (status >= 500 or status == 429):
                return ProviderUnavailable(f"gcs {op} failed: service unavailable (status={status})",
                                           provider=p)
            return StorageError(f"gcs {op} failed: transfer error ({cls_name})", provider=p)
        if isinstance(exc, TimeoutError):
            return ProviderTimeout(f"gcs {op} failed: timed out ({cls_name})", provider=p)
        if isinstance(exc, (ConnectionError, OSError)):
            return ProviderUnavailable(f"gcs {op} failed: connection failed ({cls_name})", provider=p)
        return StorageError(f"gcs {op} failed: unexpected error ({cls_name})", provider=p)

    # -- StorageProvider ---------------------------------------------------- #
    def ensure_bucket(self) -> None:
        """Create the bucket if missing (emulator / first-time setup). Never
        called implicitly. On real GCS the app identity should not be able to
        create buckets (see NOTES.md)."""
        try:
            if self._client.lookup_bucket(self.bucket_name, timeout=self._timeout, retry=None) is None:
                self._client.create_bucket(self.bucket_name, timeout=self._timeout, retry=None)
        except gexc.Conflict:
            return
        except Exception as exc:
            raise self._translate("ensure_bucket", exc) from None

    def put(self, key: str, data: bytes, metadata: Mapping[str, str] | None = None) -> ObjectInfo:
        validate_key(key)
        blob_bytes = require_bytes(data)
        meta = validate_metadata(metadata)
        blob = self._bucket.blob(key)
        if meta:
            blob.metadata = meta
        try:
            blob.upload_from_string(blob_bytes, content_type="application/octet-stream",
                                    timeout=self._timeout, retry=None)
        except Exception as exc:
            raise self._translate("put", exc) from None
        return ObjectInfo(key=key, size=len(blob_bytes), etag=blob.etag,
                          last_modified=blob.updated or utcnow(), metadata=meta)

    def get(self, key: str) -> bytes:
        validate_key(key)
        try:
            return self._bucket.blob(key).download_as_bytes(timeout=self._timeout, retry=None)
        except Exception as exc:
            raise self._translate("get", exc) from None

    def delete(self, key: str) -> None:
        validate_key(key)
        try:
            self._bucket.blob(key).delete(timeout=self._timeout, retry=None)
        except Exception as exc:
            err = self._translate("delete", exc)
            if isinstance(err, ObjectNotFound):
                return
            raise err from None

    def stat(self, key: str) -> ObjectInfo:
        validate_key(key)
        try:
            blob = self._bucket.get_blob(key, timeout=self._timeout, retry=None)
        except Exception as exc:
            raise self._translate("stat", exc) from None
        if blob is None:
            raise ObjectNotFound("gcs stat failed: object not found", provider=self.name)
        return ObjectInfo(key=key, size=int(blob.size or 0), etag=blob.etag,
                          last_modified=blob.updated, metadata=dict(blob.metadata or {}))

    def exists(self, key: str) -> bool:
        try:
            self.stat(key)
            return True
        except ObjectNotFound:
            return False

    def list_keys(self, prefix: str = "") -> Iterator[str]:
        """Lazily paginated; provider errors surface (translated) while
        iterating. The prefix is validated at call time."""
        validate_prefix(prefix)
        return self._iter_keys(prefix)

    def _iter_keys(self, prefix: str) -> Iterator[str]:
        try:
            for blob in self._client.list_blobs(self.bucket_name, prefix=prefix or None,
                                                timeout=self._timeout, retry=None):
                yield blob.name
        except GeneratorExit:
            raise
        except Exception as exc:
            raise self._translate("list", exc) from None

    def health(self) -> HealthStatus:
        """Bucket metadata GET: one cheap authenticated round trip. Never raises."""
        start = time.perf_counter()
        try:
            self._client.get_bucket(self.bucket_name, timeout=self._timeout, retry=None)
        except BaseException as exc:  # noqa: BLE001 - health must not raise
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            err = self._translate("health", exc)
            if isinstance(err, ObjectNotFound):
                err = StorageError("gcs health failed: bucket does not exist", provider=self.name)
            return HealthStatus(provider=self.name, healthy=False,
                                latency_ms=(time.perf_counter() - start) * 1000.0,
                                checked_at=utcnow(), error=error_summary(err))
        return HealthStatus(provider=self.name, healthy=True,
                            latency_ms=(time.perf_counter() - start) * 1000.0, checked_at=utcnow())
