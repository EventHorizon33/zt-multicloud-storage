"""Azure Blob Storage adapter (azure-storage-blob).

Security properties:
  * the connection string is read from settings, handed to the SDK and never
    stored on the adapter, logged, or placed in an exception message;
  * exception messages are fixed templates plus the service ``error_code`` /
    HTTP status only;
  * object keys are validated before any request;
  * SDK retries are disabled (``retry_total=0``): the orchestrator owns retry.
"""
from __future__ import annotations

import time
from typing import Any, Iterator, Mapping

from azure.core import exceptions as aexc
from azure.storage.blob import BlobServiceClient, ContentSettings

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

_TIMEOUT_CLASSES = tuple(
    c for c in (getattr(aexc, "ServiceRequestTimeoutError", None),
                getattr(aexc, "ServiceResponseTimeoutError", None)) if c is not None)


class AzureBlobProvider(StorageProvider):
    """One Azure Blob container."""

    kind = "azure"

    def __init__(
        self,
        *,
        connection_string: str | None,
        container: str,
        name: str = "azure-blob",
        timeout_seconds: float = 10.0,
        connect_timeout_seconds: float | None = None,
    ) -> None:
        if not connection_string:
            raise StorageConfigError(
                "azure provider requires a connection string (ZT_AZURE_CONNECTION_STRING)", provider=name)
        if not container:
            raise StorageConfigError("azure provider requires a container name (ZT_AZURE_CONTAINER)",
                                     provider=name)
        self.name = name
        self.container = container
        self.is_emulated = "devstoreaccount1" in connection_string
        self._timeout = timeout_seconds
        try:
            service = BlobServiceClient.from_connection_string(
                connection_string,
                connection_timeout=connect_timeout_seconds or min(timeout_seconds, 5.0),
                read_timeout=timeout_seconds,
                # no SDK retries: the orchestrator owns retry/backoff
                retry_total=0, retry_connect=0, retry_read=0, retry_status=0,
            )
            self._container = service.get_container_client(container)
        except Exception as exc:
            # The SDK's own message may quote parts of the connection string.
            raise StorageConfigError(
                f"azure client could not be created: connection string is malformed "
                f"({safe_code(type(exc).__name__)})", provider=name) from None

    @classmethod
    def from_settings(cls, settings: Any, name: str = "azure-blob") -> "AzureBlobProvider":
        return cls(
            name=name,
            connection_string=settings.azure_connection_string,
            container=settings.azure_container,
            timeout_seconds=settings.storage_timeout_seconds,
        )

    # server-side operation timeout (whole seconds, >= 1) sent with each call
    @property
    def _server_timeout(self) -> int:
        return max(1, int(self._timeout))

    # -- error translation -------------------------------------------------- #
    def _translate(self, op: str, exc: BaseException) -> StorageError:
        p = self.name
        cls_name = safe_code(type(exc).__name__)
        if isinstance(exc, StorageError):
            return exc
        if isinstance(exc, aexc.HttpResponseError):
            raw_code = getattr(exc, "error_code", None) or ""
            code = safe_code(getattr(raw_code, "value", raw_code))
            status = getattr(exc, "status_code", None)
            detail = f"code={code}, status={status}"
            if isinstance(exc, aexc.ResourceNotFoundError) or status == 404:
                if code == "ContainerNotFound":
                    return StorageError(f"azure {op} failed: container does not exist", provider=p)
                return ObjectNotFound(f"azure {op} failed: object not found", provider=p)
            if isinstance(exc, aexc.ClientAuthenticationError) or status in (401, 403):
                return ProviderAuthError(f"azure {op} failed: access denied ({detail})", provider=p)
            if status == 408 or code == "OperationTimedOut":
                return ProviderTimeout(f"azure {op} failed: request timed out ({detail})", provider=p)
            if isinstance(status, int) and (status >= 500 or status == 429):
                return ProviderUnavailable(f"azure {op} failed: service unavailable ({detail})", provider=p)
            return StorageError(f"azure {op} failed: service error ({detail})", provider=p)
        if _TIMEOUT_CLASSES and isinstance(exc, _TIMEOUT_CLASSES):
            return ProviderTimeout(f"azure {op} failed: timed out ({cls_name})", provider=p)
        if isinstance(exc, (aexc.ServiceRequestError, aexc.ServiceResponseError)):
            # azure-core wraps socket timeouts in these on some transports
            inner = getattr(exc, "inner_exception", None) or exc.__cause__
            text = f"{type(inner).__name__ if inner else ''} {cls_name}".lower()
            if "timeout" in text or "timed out" in str(getattr(exc, "message", "")).lower():
                return ProviderTimeout(f"azure {op} failed: timed out ({cls_name})", provider=p)
            return ProviderUnavailable(f"azure {op} failed: connection failed ({cls_name})", provider=p)
        if isinstance(exc, aexc.AzureError):
            return StorageError(f"azure {op} failed: sdk error ({cls_name})", provider=p)
        if isinstance(exc, TimeoutError):
            return ProviderTimeout(f"azure {op} failed: timed out ({cls_name})", provider=p)
        if isinstance(exc, (ConnectionError, OSError)):
            return ProviderUnavailable(f"azure {op} failed: connection failed ({cls_name})", provider=p)
        return StorageError(f"azure {op} failed: unexpected error ({cls_name})", provider=p)

    # -- StorageProvider ---------------------------------------------------- #
    def ensure_bucket(self) -> None:
        """Create the container if missing (emulator / first-time setup).
        Never called implicitly."""
        try:
            self._container.create_container(timeout=self._server_timeout)
        except aexc.ResourceExistsError:
            return
        except Exception as exc:
            raise self._translate("ensure_bucket", exc) from None

    def put(self, key: str, data: bytes, metadata: Mapping[str, str] | None = None) -> ObjectInfo:
        validate_key(key)
        blob = require_bytes(data)
        meta = validate_metadata(metadata)
        try:
            # upload_blob on a container client returns a BlobClient, not the
            # response headers, so no etag is reported (stat() provides it).
            self._container.upload_blob(
                name=key, data=blob, length=len(blob), overwrite=True, metadata=meta or None,
                content_settings=ContentSettings(content_type="application/octet-stream"),
                timeout=self._server_timeout)
        except Exception as exc:
            raise self._translate("put", exc) from None
        return ObjectInfo(key=key, size=len(blob), etag=None, last_modified=utcnow(), metadata=meta)

    def get(self, key: str) -> bytes:
        validate_key(key)
        try:
            return self._container.download_blob(key, timeout=self._server_timeout).readall()
        except Exception as exc:
            raise self._translate("get", exc) from None

    def delete(self, key: str) -> None:
        validate_key(key)
        try:
            self._container.delete_blob(key, timeout=self._server_timeout)
        except Exception as exc:
            err = self._translate("delete", exc)
            if isinstance(err, ObjectNotFound):
                return
            raise err from None

    def stat(self, key: str) -> ObjectInfo:
        validate_key(key)
        try:
            props = self._container.get_blob_client(key).get_blob_properties(timeout=self._server_timeout)
        except Exception as exc:
            raise self._translate("stat", exc) from None
        etag = props.etag.strip('"') if props.etag else None
        return ObjectInfo(key=key, size=int(props.size or 0), etag=etag,
                          last_modified=props.last_modified, metadata=dict(props.metadata or {}))

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
            for name in self._container.list_blob_names(
                    name_starts_with=prefix or None, timeout=self._server_timeout):
                yield name
        except GeneratorExit:
            raise
        except Exception as exc:
            raise self._translate("list", exc) from None

    def health(self) -> HealthStatus:
        """Container properties: one cheap authenticated round trip. Never raises."""
        start = time.perf_counter()
        try:
            self._container.get_container_properties(timeout=self._server_timeout)
        except BaseException as exc:  # noqa: BLE001 - health must not raise
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            return HealthStatus(provider=self.name, healthy=False,
                                latency_ms=(time.perf_counter() - start) * 1000.0,
                                checked_at=utcnow(),
                                error=error_summary(self._translate("health", exc)))
        return HealthStatus(provider=self.name, healthy=True,
                            latency_ms=(time.perf_counter() - start) * 1000.0, checked_at=utcnow())
