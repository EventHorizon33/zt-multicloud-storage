"""Fault injection wrapper. FOR DEMONSTRATIONS AND TESTS ONLY.

``build_providers`` wraps providers in ``FaultInjectingProvider`` only when
fault injection is explicitly enabled, and ``Settings`` refuses that in
production. Every injected error is an ``Injected*`` subclass with
``injected = True`` and a message starting with ``injected fault``, and
``status()`` reports ``injected: True`` while a fault mode is active, so an
injected failure can never be mistaken for a real outage in reports.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Callable, Iterator, Mapping

from app.contracts import (
    HealthStatus,
    ObjectInfo,
    ProviderTimeout,
    ProviderUnavailable,
    StorageProvider,
)

from ._common import require_bytes, utcnow, validate_key, validate_metadata

MODES = ("none", "unavailable", "timeout", "corrupt-reads", "fail-n", "drop-writes", "slow")


class InjectedUnavailable(ProviderUnavailable):
    injected = True


class InjectedTimeout(ProviderTimeout):
    injected = True


class FaultInjectingProvider(StorageProvider):
    """Wraps a real provider and misbehaves on demand.

    Modes (``set_mode(mode, **params)``):
      none           pass-through
      unavailable    every operation (and health) fails with ProviderUnavailable
      timeout        every operation waits ``delay`` seconds (default 0) then
                     raises ProviderTimeout; health reports unhealthy
      corrupt-reads  get() returns the stored bytes with bits flipped
      fail-n         the next ``n`` data operations (default 1) raise
                     ProviderUnavailable, then the provider recovers
      drop-writes    put() reports success but stores nothing (lying provider)
      slow           every operation waits ``delay`` seconds (default 0.05)
                     then passes through
    Health probes do not consume the fail-n budget."""

    def __init__(self, inner: StorageProvider, *, sleep: Callable[[float], None] = time.sleep) -> None:
        self.inner = inner
        self.name = inner.name
        self.kind = inner.kind
        self._sleep = sleep
        self._lock = threading.Lock()
        self._mode = "none"
        self._params: dict[str, Any] = {}
        self._remaining = 0
        self._injected_count = 0

    # -- control ------------------------------------------------------------ #
    def set_mode(self, mode: str, **params: Any) -> dict[str, Any]:
        if mode not in MODES:
            raise ValueError(f"unknown fault mode {mode!r}; expected one of {', '.join(MODES)}")
        allowed = {"fail-n": {"n"}, "timeout": {"delay"}, "slow": {"delay"}}.get(mode, set())
        unknown = set(params) - allowed
        if unknown:
            raise ValueError(f"unsupported parameter(s) for mode {mode!r}: {', '.join(sorted(unknown))}")
        clean: dict[str, Any] = {}
        if mode == "fail-n":
            n = int(params.get("n", 1))
            if n < 0:
                raise ValueError("n must be >= 0")
            clean["n"] = n
        if mode in ("timeout", "slow"):
            delay = float(params.get("delay", 0.0 if mode == "timeout" else 0.05))
            if not 0 <= delay <= 30:
                raise ValueError("delay must be between 0 and 30 seconds")
            clean["delay"] = delay
        with self._lock:
            self._mode = mode
            self._params = clean
            self._remaining = clean.get("n", 0)
        return self.status()

    def clear(self) -> None:
        self.set_mode("none")

    @property
    def mode(self) -> str:
        with self._lock:
            return self._mode

    def status(self) -> dict[str, Any]:
        with self._lock:
            active = self._mode != "none" and not (self._mode == "fail-n" and self._remaining == 0)
            return {"provider": self.name, "mode": self._mode, "params": dict(self._params),
                    "remaining_failures": self._remaining if self._mode == "fail-n" else None,
                    "injected": active, "fault_injection_enabled": True,
                    "injected_failures_total": self._injected_count}

    # -- internals ---------------------------------------------------------- #
    def _before(self, op: str) -> str:
        """Apply mode effects that happen before the real call. Returns the
        mode in force for this call."""
        with self._lock:
            mode, params = self._mode, dict(self._params)
            if mode == "fail-n":
                if self._remaining > 0:
                    self._remaining -= 1
                    self._injected_count += 1
                    raise InjectedUnavailable(f"injected fault: provider unavailable (fail-n, op={op})",
                                              provider=self.name)
            elif mode == "unavailable":
                self._injected_count += 1
                raise InjectedUnavailable(f"injected fault: provider unavailable (op={op})",
                                          provider=self.name)
        if mode == "timeout":
            if params.get("delay"):
                self._sleep(params["delay"])
            with self._lock:
                self._injected_count += 1
            raise InjectedTimeout(f"injected fault: provider timed out (op={op})", provider=self.name)
        if mode == "slow" and params.get("delay"):
            self._sleep(params["delay"])
        return mode

    # -- StorageProvider ---------------------------------------------------- #
    def ensure_bucket(self) -> None:
        fn = getattr(self.inner, "ensure_bucket", None)
        if fn is not None:
            fn()

    def put(self, key: str, data: bytes, metadata: Mapping[str, str] | None = None) -> ObjectInfo:
        mode = self._before("put")
        if mode == "drop-writes":
            validate_key(key)
            blob = require_bytes(data)
            with self._lock:
                self._injected_count += 1
            return ObjectInfo(key=key, size=len(blob), etag=None, last_modified=utcnow(),
                              metadata=validate_metadata(metadata))
        return self.inner.put(key, data, metadata)

    def get(self, key: str) -> bytes:
        mode = self._before("get")
        data = self.inner.get(key)
        if mode == "corrupt-reads":
            with self._lock:
                self._injected_count += 1
            return _corrupt(data)
        return data

    def delete(self, key: str) -> None:
        self._before("delete")
        self.inner.delete(key)

    def exists(self, key: str) -> bool:
        self._before("exists")
        return self.inner.exists(key)

    def stat(self, key: str) -> ObjectInfo:
        self._before("stat")
        return self.inner.stat(key)

    def list_keys(self, prefix: str = "") -> Iterator[str]:
        self._before("list")
        return self.inner.list_keys(prefix)

    def health(self) -> HealthStatus:
        with self._lock:
            mode, params = self._mode, dict(self._params)
        if mode in ("unavailable", "timeout"):
            if mode == "timeout" and params.get("delay"):
                self._sleep(params["delay"])
            return HealthStatus(provider=self.name, healthy=False, latency_ms=None, checked_at=utcnow(),
                                error=f"injected fault: {mode}")
        if mode == "slow" and params.get("delay"):
            self._sleep(params["delay"])
        try:
            return self.inner.health()
        except Exception as exc:  # inner violated its contract; still never raise
            return HealthStatus(provider=self.name, healthy=False, latency_ms=None, checked_at=utcnow(),
                                error=f"health probe raised {type(exc).__name__}")


def _corrupt(data: bytes) -> bytes:
    """Flip every bit of the first byte, a middle byte and the last byte (an
    empty object becomes one garbage byte), so any hash check must fail."""
    if not data:
        return b"\xff"
    buf = bytearray(data)
    for i in {0, len(buf) // 2, len(buf) - 1}:
        buf[i] ^= 0xFF
    return bytes(buf)


def is_injected(exc: BaseException) -> bool:
    return bool(getattr(exc, "injected", False))


__all__ = ["FaultInjectingProvider", "InjectedTimeout", "InjectedUnavailable", "MODES", "is_injected"]
