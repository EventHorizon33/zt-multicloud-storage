"""Bounded retry with exponential backoff + full jitter, and a per-call
deadline guard.

Security / availability properties:
  * retries are bounded (``max_attempts``) and delays are capped
    (``max_delay``), so a failing provider cannot make a request loop forever;
  * only errors that declare ``retryable = True`` are retried. ObjectNotFound
    and ProviderAuthError are never retried (retrying bad credentials only adds
    lockout risk and noise);
  * ``DeadlineRunner`` bounds the wall time a caller waits for one provider
    call, even if the SDK's own socket timeouts fail to fire.
"""
from __future__ import annotations

import contextvars
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from typing import Callable, TypeVar

from app.contracts import ObjectNotFound, ProviderAuthError, ProviderTimeout, StorageError

from ._common import safe_code

T = TypeVar("T")

_NEVER_RETRY: tuple[type[StorageError], ...] = (ObjectNotFound, ProviderAuthError)


@dataclass(frozen=True)
class RetryPolicy:
    """``max_attempts`` counts the first try (1 = no retries). Delay before
    retry number k (k = 1, 2, ...) is drawn uniformly from
    ``[0, min(max_delay, base_delay * 2**(k-1))]`` when ``jitter`` is true
    ("full jitter"), else it is exactly that cap."""

    max_attempts: int = 4
    base_delay: float = 0.2
    max_delay: float = 3.0
    jitter: bool = True

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if self.base_delay < 0 or self.max_delay < 0:
            raise ValueError("delays must be >= 0")
        if self.max_delay < self.base_delay:
            raise ValueError("max_delay must be >= base_delay")

    @classmethod
    def from_settings(cls, settings: object) -> "RetryPolicy":
        return cls(max_attempts=settings.retry_max_attempts,            # type: ignore[attr-defined]
                   base_delay=settings.retry_base_delay_seconds,        # type: ignore[attr-defined]
                   max_delay=settings.retry_max_delay_seconds)          # type: ignore[attr-defined]

    def backoff_cap(self, retry_number: int) -> float:
        """Upper bound of the delay before retry ``retry_number`` (1-based)."""
        if retry_number < 1:
            raise ValueError("retry_number is 1-based")
        exp = min(retry_number - 1, 62)  # avoid float overflow for silly inputs
        return min(self.max_delay, self.base_delay * (2 ** exp))

    def backoff(self, retry_number: int, rng: random.Random | None = None) -> float:
        cap = self.backoff_cap(retry_number)
        if not self.jitter:
            return cap
        return (rng or _RNG).uniform(0.0, cap)


# Jitter only needs to be unpredictable enough to de-synchronise clients; it
# is not security-relevant, so the shared PRNG (seeded from os.urandom) is fine.
_RNG = random.Random()


def is_retryable(exc: BaseException) -> bool:
    """True only for StorageErrors that declare ``retryable`` and are not in
    the never-retry set."""
    if not isinstance(exc, StorageError) or isinstance(exc, _NEVER_RETRY):
        return False
    return bool(getattr(exc, "retryable", False))


def call_with_retry(
    fn: Callable[[], T],
    policy: RetryPolicy,
    *,
    sleep: Callable[[float], None] = time.sleep,
    on_retry: Callable[[int, BaseException, float], None] | None = None,
    rng: random.Random | None = None,
) -> T:
    """Call ``fn`` until it succeeds, raises a non-retryable error, or
    ``policy.max_attempts`` attempts have been made; then re-raise the last
    error. ``on_retry(retry_number, exc, delay)`` is called before each
    backoff sleep. ``sleep`` is injectable so tests never actually wait."""
    attempt = 0
    while True:
        attempt += 1
        try:
            return fn()
        except BaseException as exc:
            if not is_retryable(exc) or attempt >= policy.max_attempts:
                raise
            delay = policy.backoff(attempt, rng)
            if on_retry is not None:
                on_retry(attempt, exc, delay)
            if delay > 0:
                sleep(delay)


class DeadlineRunner:
    """Runs provider calls on a shared bounded thread pool and waits at most
    ``timeout`` seconds for each.

    CAVEAT: Python cannot kill a thread. When the deadline passes, the caller
    gets ``ProviderTimeout`` immediately, but the worker thread keeps running
    the hung SDK call until the SDK's own socket timeout (or the OS) ends it.
    The pool is bounded (``max_workers``), so a provider that hangs every call
    can occupy every worker; further calls then queue and also hit their
    deadline (fail closed, never unbounded thread growth). Time spent queued
    counts toward the deadline. SDK connect/read timeouts remain the primary
    mechanism; this is the backstop."""

    def __init__(self, max_workers: int = 64, thread_name_prefix: str = "zt-storage-io") -> None:
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix=thread_name_prefix)
        self._closed = False
        self._lock = threading.Lock()

    def call(self, fn: Callable[[], T], timeout: float | None, *, provider: str | None = None,
             op: str = "call") -> T:
        if timeout is None or timeout <= 0:
            return fn()
        with self._lock:
            if self._closed:
                raise StorageError("storage deadline runner is shut down", provider=provider)
            future = self._pool.submit(contextvars.copy_context().run, fn)   # keep audit context (F5)
        try:
            return future.result(timeout=timeout)
        except FutureTimeout:
            future.cancel()  # effective only if it never started
            raise ProviderTimeout(
                f"{safe_code(op)} exceeded the {timeout:g}s deadline", provider=provider) from None

    def shutdown(self) -> None:
        with self._lock:
            self._closed = True
        self._pool.shutdown(wait=False, cancel_futures=True)
