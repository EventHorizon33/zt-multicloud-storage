"""Multi-cloud storage layer (Phase 4).

Only opaque object keys and ciphertext bytes pass through this package. See
NOTES.md for the public API and its limits.
"""
from __future__ import annotations

import re
from typing import Any

from app.contracts import AuditSink, StorageProvider

from ._common import ANCHOR_PREFIX, InvalidObjectKey, StorageConfigError, validate_key
from .faults import FaultInjectingProvider
from .health import HealthMonitor
from .metrics import StorageMetrics
from .orchestrator import (
    AnchorListing,
    AnchorRead,
    AnchorWriteResult,
    ChunkStoreError,
    ChunkUnavailableError,
    CircuitOpenError,
    DeleteResult,
    FaultInjectionDisabled,
    FetchResult,
    ProviderFailure,
    ReplicaAttempt,
    StorageOrchestrator,
    StoreResult,
    WriteVerificationError,
)
from .placement import HashPlacement, PlacementStrategy, RotatingPlacement, placement_from_name
from .retry import DeadlineRunner, RetryPolicy, call_with_retry

_MEMORY_NAME = re.compile(r"^memory(-[a-z0-9]+)?$")
KNOWN_PROVIDERS = ("aws-s3", "azure-blob", "gcs")


def build_providers(settings: Any, *, enable_fault_injection: bool | None = None) -> dict[str, StorageProvider]:
    """Instantiate the providers named in ``settings.provider_names``.

    "aws-s3" -> S3Provider, "azure-blob" -> AzureBlobProvider, "gcs" ->
    GCSProvider; "memory" / "memory-<x>" -> MemoryProvider ONLY when
    ``settings.env == "test"``. Unknown or duplicate names and missing
    required settings raise StorageConfigError (naming the setting, never its
    value). With fault injection enabled (argument, else
    ``settings.enable_fault_injection``) every provider is wrapped in
    FaultInjectingProvider; this is refused in production."""
    names = list(settings.provider_names)
    if not names:
        raise StorageConfigError("no storage providers configured (ZT_STORAGE_PROVIDERS)")
    if len(set(names)) != len(names):
        raise StorageConfigError("duplicate provider name in ZT_STORAGE_PROVIDERS")
    inject = settings.enable_fault_injection if enable_fault_injection is None else enable_fault_injection
    if inject and settings.env == "production":
        raise StorageConfigError("fault injection cannot be enabled in production")

    providers: dict[str, StorageProvider] = {}
    for name in names:
        provider: StorageProvider
        if name == "aws-s3":
            from .s3 import S3Provider
            provider = S3Provider.from_settings(settings, name=name)
        elif name == "azure-blob":
            from .azure import AzureBlobProvider
            provider = AzureBlobProvider.from_settings(settings, name=name)
        elif name == "gcs":
            from .gcs import GCSProvider
            provider = GCSProvider.from_settings(settings, name=name)
        elif _MEMORY_NAME.match(name):
            if settings.env != "test":
                raise StorageConfigError(
                    f"provider {name!r}: in-memory providers are only allowed when ZT_ENV=test")
            from .memory import MemoryProvider
            provider = MemoryProvider(name)
        else:
            raise StorageConfigError(
                f"unknown storage provider {name!r}; expected one of {', '.join(KNOWN_PROVIDERS)}")
        providers[name] = FaultInjectingProvider(provider) if inject else provider
    return providers


def build_orchestrator(
    settings: Any,
    *,
    providers: dict[str, StorageProvider] | None = None,
    audit: AuditSink | None = None,
    health: HealthMonitor | None = None,
    metrics: StorageMetrics | None = None,
    enable_fault_injection: bool | None = None,
) -> StorageOrchestrator:
    """Convenience wiring from Settings. Creates a HealthMonitor (not started)
    if none is given; call ``orchestrator.health.start()`` to probe in the
    background."""
    providers = providers or build_providers(settings, enable_fault_injection=enable_fault_injection)
    if health is None:
        health = HealthMonitor(providers, interval=settings.health_check_interval_seconds, audit=audit)
    return StorageOrchestrator(
        providers,
        placement_from_name(settings.placement_strategy),
        RetryPolicy.from_settings(settings),
        health,
        replication_factor=settings.replication_factor,
        min_write_replicas=settings.min_write_replicas,
        audit=audit,
        timeout_seconds=settings.storage_timeout_seconds,
        metrics=metrics,
    )


__all__ = [
    "ANCHOR_PREFIX", "AnchorListing", "AnchorRead", "AnchorWriteResult", "ChunkStoreError",
    "ChunkUnavailableError", "CircuitOpenError", "DeadlineRunner", "DeleteResult", "FaultInjectingProvider",
    "FaultInjectionDisabled", "FetchResult", "HashPlacement", "HealthMonitor", "InvalidObjectKey",
    "PlacementStrategy", "ProviderFailure", "ReplicaAttempt", "RetryPolicy", "RotatingPlacement",
    "StorageConfigError", "StorageMetrics", "StorageOrchestrator", "StoreResult", "WriteVerificationError",
    "build_orchestrator", "build_providers", "call_with_retry", "placement_from_name", "validate_key",
]
