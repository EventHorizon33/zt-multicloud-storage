"""AWS S3 adapter (boto3). Also works against S3-compatible endpoints
(moto server, MinIO) when ``endpoint_url`` is set.

Security properties:
  * credentials come from settings or the default AWS credential chain; none
    are hardcoded, logged, or placed in exception messages;
  * exception messages are built from fixed templates plus the service error
    *code* only (never the SDK message, URL or headers);
  * object keys are validated before any request is made;
  * botocore retries are disabled: the orchestrator owns retry policy, so a
    single call here is a single bounded network attempt.
"""
from __future__ import annotations

import time
from typing import Any, Iterator, Mapping

import boto3
from botocore import exceptions as bexc
from botocore.config import Config

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

_AUTH_CODES = {
    "AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch", "ExpiredToken",
    "InvalidToken", "TokenRefreshRequired", "AccountProblem", "AllAccessDisabled",
    "InvalidSecurity", "NotSignedUp", "RequestTimeTooSkewed", "UnauthorizedAccess",
    "AuthorizationHeaderMalformed", "InvalidClientTokenId", "UnrecognizedClientException",
}
_NOT_FOUND_CODES = {"NoSuchKey", "404", "NotFound"}
_TIMEOUT_CODES = {"RequestTimeout", "RequestTimeoutException"}
_UNAVAILABLE_CODES = {
    "SlowDown", "ServiceUnavailable", "InternalError", "Throttling", "ThrottlingException",
    "RequestLimitExceeded", "TooManyRequestsException", "503", "500", "502", "504",
}


class S3Provider(StorageProvider):
    """One S3 bucket."""

    kind = "s3"

    def __init__(
        self,
        *,
        bucket: str,
        name: str = "aws-s3",
        region: str = "us-east-1",
        endpoint_url: str | None = None,
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        timeout_seconds: float = 10.0,
        connect_timeout_seconds: float | None = None,
    ) -> None:
        if not bucket:
            raise StorageConfigError("s3 provider requires a bucket name (ZT_S3_BUCKET)", provider=name)
        if bool(access_key_id) != bool(secret_access_key):
            raise StorageConfigError(
                "s3 provider needs both ZT_S3_ACCESS_KEY_ID and ZT_S3_SECRET_ACCESS_KEY, or neither "
                "(to use the default AWS credential chain)", provider=name)
        self.name = name
        self.bucket = bucket
        self.region = region
        self.is_emulated = bool(endpoint_url)
        cfg: dict[str, Any] = {
            "connect_timeout": connect_timeout_seconds or min(timeout_seconds, 5.0),
            "read_timeout": timeout_seconds,
            # one attempt in total: the orchestrator owns retry/backoff
            "retries": {"total_max_attempts": 1, "mode": "standard"},
            "signature_version": "s3v4",
            "max_pool_connections": 32,
        }
        if endpoint_url:
            cfg["s3"] = {"addressing_style": "path"}
        kwargs: dict[str, Any] = {"region_name": region, "config": Config(**cfg)}
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url
        if access_key_id and secret_access_key:
            kwargs["aws_access_key_id"] = access_key_id
            kwargs["aws_secret_access_key"] = secret_access_key
        try:
            self._client = boto3.session.Session().client("s3", **kwargs)
        except Exception as exc:  # e.g. malformed endpoint url
            raise StorageConfigError(
                f"s3 client could not be created ({safe_code(type(exc).__name__)})", provider=name) from None

    @classmethod
    def from_settings(cls, settings: Any, name: str = "aws-s3") -> "S3Provider":
        return cls(
            name=name,
            bucket=settings.s3_bucket,
            region=settings.s3_region,
            endpoint_url=settings.s3_endpoint_url,
            access_key_id=settings.s3_access_key_id,
            secret_access_key=settings.s3_secret_access_key,
            timeout_seconds=settings.storage_timeout_seconds,
        )

    # -- error translation -------------------------------------------------- #
    def _translate(self, op: str, exc: BaseException) -> StorageError:
        """Map a botocore exception to the StorageError hierarchy. Only the
        operation name, exception class and service error code are used."""
        p = self.name
        cls_name = safe_code(type(exc).__name__)
        if isinstance(exc, StorageError):
            return exc
        if isinstance(exc, bexc.ClientError):
            err = exc.response.get("Error", {}) if isinstance(exc.response, dict) else {}
            code = str(err.get("Code", ""))
            status = (exc.response.get("ResponseMetadata", {}) or {}).get("HTTPStatusCode") \
                if isinstance(exc.response, dict) else None
            detail = f"code={safe_code(code)}, status={status}"
            if code in _NOT_FOUND_CODES or (status == 404 and code != "NoSuchBucket"):
                return ObjectNotFound(f"s3 {op} failed: object not found", provider=p)
            if code == "NoSuchBucket":
                return StorageError(f"s3 {op} failed: bucket does not exist", provider=p)
            if code in _AUTH_CODES or status in (401, 403):
                return ProviderAuthError(f"s3 {op} failed: access denied ({detail})", provider=p)
            if code in _TIMEOUT_CODES or status == 408:
                return ProviderTimeout(f"s3 {op} failed: request timed out ({detail})", provider=p)
            if code in _UNAVAILABLE_CODES or (isinstance(status, int) and (status >= 500 or status == 429)):
                return ProviderUnavailable(f"s3 {op} failed: service unavailable ({detail})", provider=p)
            return StorageError(f"s3 {op} failed: service error ({detail})", provider=p)
        if isinstance(exc, (bexc.ConnectTimeoutError, bexc.ReadTimeoutError)):
            return ProviderTimeout(f"s3 {op} failed: timed out ({cls_name})", provider=p)
        if isinstance(exc, (bexc.NoCredentialsError, bexc.PartialCredentialsError,
                            bexc.CredentialRetrievalError, bexc.TokenRetrievalError)):
            return ProviderAuthError(f"s3 {op} failed: no usable credentials ({cls_name})", provider=p)
        if isinstance(exc, (bexc.EndpointConnectionError, bexc.ConnectionClosedError,
                            bexc.ConnectionError, bexc.HTTPClientError, bexc.IncompleteReadError,
                            bexc.ResponseStreamingError)):
            return ProviderUnavailable(f"s3 {op} failed: connection failed ({cls_name})", provider=p)
        if isinstance(exc, TimeoutError):
            return ProviderTimeout(f"s3 {op} failed: timed out ({cls_name})", provider=p)
        if isinstance(exc, (ConnectionError, OSError)):
            return ProviderUnavailable(f"s3 {op} failed: connection failed ({cls_name})", provider=p)
        return StorageError(f"s3 {op} failed: unexpected error ({cls_name})", provider=p)

    # -- StorageProvider ---------------------------------------------------- #
    def ensure_bucket(self) -> None:
        """Create the bucket if it does not exist. Intended for emulators and
        first-time setup; never called implicitly. On real AWS the application
        identity should NOT have ``s3:CreateBucket`` (see NOTES.md)."""
        try:
            self._client.head_bucket(Bucket=self.bucket)
            return
        except bexc.ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code not in ("404", "NoSuchBucket", "NotFound"):
                raise self._translate("ensure_bucket", exc) from None
        except Exception as exc:
            raise self._translate("ensure_bucket", exc) from None
        try:
            params: dict[str, Any] = {"Bucket": self.bucket}
            if self.region != "us-east-1":
                params["CreateBucketConfiguration"] = {"LocationConstraint": self.region}
            self._client.create_bucket(**params)
        except bexc.ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
                return
            raise self._translate("ensure_bucket", exc) from None
        except Exception as exc:
            raise self._translate("ensure_bucket", exc) from None

    def put(self, key: str, data: bytes, metadata: Mapping[str, str] | None = None) -> ObjectInfo:
        validate_key(key)
        blob = require_bytes(data)
        meta = validate_metadata(metadata)
        try:
            resp = self._client.put_object(
                Bucket=self.bucket, Key=key, Body=blob, Metadata=meta,
                ContentType="application/octet-stream")
        except Exception as exc:
            raise self._translate("put", exc) from None
        etag = resp.get("ETag")
        return ObjectInfo(key=key, size=len(blob), etag=etag.strip('"') if etag else None,
                          last_modified=utcnow(), metadata=meta)

    def get(self, key: str) -> bytes:
        validate_key(key)
        try:
            resp = self._client.get_object(Bucket=self.bucket, Key=key)
            body = resp["Body"]
            try:
                return body.read()
            finally:
                body.close()
        except Exception as exc:
            raise self._translate("get", exc) from None

    def delete(self, key: str) -> None:
        validate_key(key)
        try:
            self._client.delete_object(Bucket=self.bucket, Key=key)
        except Exception as exc:
            err = self._translate("delete", exc)
            if isinstance(err, ObjectNotFound):
                return
            raise err from None

    def stat(self, key: str) -> ObjectInfo:
        validate_key(key)
        try:
            resp = self._client.head_object(Bucket=self.bucket, Key=key)
        except Exception as exc:
            raise self._translate("stat", exc) from None
        etag = resp.get("ETag")
        return ObjectInfo(key=key, size=int(resp.get("ContentLength", 0)),
                          etag=etag.strip('"') if etag else None,
                          last_modified=resp.get("LastModified"),
                          metadata=dict(resp.get("Metadata") or {}))

    def exists(self, key: str) -> bool:
        try:
            self.stat(key)
            return True
        except ObjectNotFound:
            return False

    def list_keys(self, prefix: str = "") -> Iterator[str]:
        """Lazily paginated. Provider errors surface (translated) while
        iterating, not at call time; the prefix is validated at call time."""
        validate_prefix(prefix)
        return self._iter_keys(prefix)

    def _iter_keys(self, prefix: str) -> Iterator[str]:
        token: str | None = None
        while True:
            params: dict[str, Any] = {"Bucket": self.bucket, "Prefix": prefix}
            if token:
                params["ContinuationToken"] = token
            try:
                resp = self._client.list_objects_v2(**params)
            except Exception as exc:
                raise self._translate("list", exc) from None
            for item in resp.get("Contents", []) or []:
                yield item["Key"]
            if not resp.get("IsTruncated"):
                return
            token = resp.get("NextContinuationToken")
            if not token:
                return

    def _health_error(self, exc: BaseException) -> StorageError:
        err = self._translate("health", exc)
        if isinstance(err, ObjectNotFound):  # HEAD bucket 404 = missing bucket
            return StorageError("s3 health failed: bucket does not exist", provider=self.name)
        return err

    def health(self) -> HealthStatus:
        """HEAD bucket: one cheap authenticated round trip. Never raises."""
        start = time.perf_counter()
        try:
            self._client.head_bucket(Bucket=self.bucket)
        except BaseException as exc:  # noqa: BLE001 - health must not raise
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            return HealthStatus(provider=self.name, healthy=False,
                                latency_ms=(time.perf_counter() - start) * 1000.0,
                                checked_at=utcnow(),
                                error=error_summary(self._health_error(exc)))
        return HealthStatus(provider=self.name, healthy=True,
                            latency_ms=(time.perf_counter() - start) * 1000.0, checked_at=utcnow())
