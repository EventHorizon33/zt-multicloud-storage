"""Key management: local encrypted keystore and AWS KMS adapter.

Integrators call :func:`build_kms` and depend only on
``app.contracts.KeyManagementService``. See NOTES.md.
"""
from __future__ import annotations

from typing import Any

from app.contracts import KeyManagementService
from app.errors import KmsError

from .local import LocalKMS, load_root_key

__all__ = ["LocalKMS", "AwsKMS", "build_kms", "load_root_key"]


def __getattr__(name: str) -> Any:
    # AwsKMS is imported lazily so a local-only deployment never imports boto3.
    if name == "AwsKMS":
        from .aws import AwsKMS
        return AwsKMS
    raise AttributeError(name)


def build_kms(settings: Any) -> KeyManagementService:
    """Construct the KMS selected by ``settings.kms_backend`` ("local" | "aws").

    * ``local``: :class:`LocalKMS` at ``settings.kms_keystore_path`` under the
      root key from :func:`load_root_key`.
    * ``aws``: :class:`AwsKMS` on ``settings.aws_kms_key_id`` for data-key and
      secret encryption, with a :class:`LocalKMS` (same keystore/root-key
      settings) for signing and MAC keys.

    Raises :class:`KmsError` for an unknown backend or missing configuration.
    """
    backend = getattr(settings, "kms_backend", "local")
    if backend not in ("local", "aws"):
        raise KmsError(f"unknown kms_backend {backend!r} (expected 'local' or 'aws')")
    if backend == "aws" and not getattr(settings, "aws_kms_key_id", None):
        raise KmsError("kms_backend 'aws' requires ZT_AWS_KMS_KEY_ID")

    keystore_path = getattr(settings, "kms_keystore_path", None)
    if keystore_path is None:
        raise KmsError("kms_keystore_path is not configured")
    local = LocalKMS(keystore_path, load_root_key(settings))
    if backend == "local":
        return local

    from .aws import AwsKMS
    try:
        import boto3
        region = boto3.session.Session().region_name or getattr(settings, "s3_region", None)
    except Exception as exc:
        raise KmsError(f"could not initialise boto3 ({type(exc).__name__})") from None
    return AwsKMS(settings.aws_kms_key_id, local,
                  endpoint_url=getattr(settings, "aws_kms_endpoint_url", None),
                  region_name=region)
