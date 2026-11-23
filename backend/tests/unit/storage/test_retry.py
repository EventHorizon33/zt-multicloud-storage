import random
import threading
import time

import pytest

from app.contracts import ObjectNotFound, ProviderAuthError, ProviderTimeout, ProviderUnavailable, StorageError
from app.storage import DeadlineRunner, RetryPolicy, call_with_retry
from app.storage.retry import is_retryable


class Flaky:
    def __init__(self, failures, exc=ProviderUnavailable, result="ok"):
        self.failures, self.exc, self.result, self.calls = failures, exc, result, 0

    def __call__(self):
        self.calls += 1
        if self.calls <= self.failures:
            if issubclass(self.exc, StorageError):
                raise self.exc("boom", provider="p")
            raise self.exc("boom")
        return self.result


def test_policy_validation():
    with pytest.raises(ValueError):
        RetryPolicy(max_attempts=0)
    with pytest.raises(ValueError):
        RetryPolicy(base_delay=1, max_delay=0.5)
    with pytest.raises(ValueError):
        RetryPolicy(base_delay=-1)


def test_backoff_cap_grows_exponentially_and_is_bounded():
    p = RetryPolicy(max_attempts=10, base_delay=0.1, max_delay=1.0, jitter=False)
    assert [p.backoff(k) for k in range(1, 7)] == pytest.approx([0.1, 0.2, 0.4, 0.8, 1.0, 1.0])
    assert p.backoff_cap(1000) == 1.0  # no overflow


def test_full_jitter_range():
    p = RetryPolicy(max_attempts=10, base_delay=0.1, max_delay=1.0, jitter=True)
    rng = random.Random(7)
    for k in range(1, 8):
        cap = p.backoff_cap(k)
        samples = [p.backoff(k, rng) for _ in range(300)]
        assert all(0.0 <= s <= cap for s in samples)
        assert max(samples) > cap * 0.8 and min(samples) < cap * 0.2  # actually spread out


def test_retry_then_success_uses_injected_sleep():
    sleeps, retries = [], []
    fn = Flaky(2)
    out = call_with_retry(fn, RetryPolicy(4, 0.1, 1.0, jitter=False), sleep=sleeps.append,
                          on_retry=lambda n, e, d: retries.append((n, type(e).__name__, d)))
    assert out == "ok" and fn.calls == 3
    assert sleeps == pytest.approx([0.1, 0.2])
    assert retries == [(1, "ProviderUnavailable", pytest.approx(0.1)), (2, "ProviderUnavailable", pytest.approx(0.2))]


def test_max_attempts_bounds_calls_and_reraises_last_error():
    sleeps = []
    fn = Flaky(100, ProviderTimeout)
    with pytest.raises(ProviderTimeout):
        call_with_retry(fn, RetryPolicy(3, 0.01, 0.02), sleep=sleeps.append)
    assert fn.calls == 3 and len(sleeps) == 2


@pytest.mark.parametrize("exc", [ObjectNotFound, ProviderAuthError, StorageError, ValueError])
def test_non_retryable_errors_are_not_retried(exc):
    fn = Flaky(5, exc)
    sleeps = []
    with pytest.raises(exc):
        call_with_retry(fn, RetryPolicy(5, 0.01, 0.02), sleep=sleeps.append)
    assert fn.calls == 1 and sleeps == []


def test_never_retry_even_if_flag_forced():
    class Weird(ObjectNotFound):
        retryable = True
    assert not is_retryable(Weird("x"))
    assert is_retryable(ProviderUnavailable("x")) and is_retryable(ProviderTimeout("x"))


def test_no_real_sleep_happens():
    t0 = time.perf_counter()
    with pytest.raises(ProviderUnavailable):
        call_with_retry(Flaky(100), RetryPolicy(6, 10.0, 60.0), sleep=lambda s: None)
    assert time.perf_counter() - t0 < 0.5


def test_deadline_runner_times_out_hung_call():
    runner = DeadlineRunner(max_workers=2)
    release = threading.Event()
    t0 = time.perf_counter()
    with pytest.raises(ProviderTimeout) as ei:
        runner.call(lambda: release.wait(5), 0.1, provider="p", op="get")
    assert time.perf_counter() - t0 < 1.0
    assert ei.value.provider == "p" and ei.value.retryable
    release.set()
    assert runner.call(lambda: 42, 1.0) == 42
    runner.shutdown()
    with pytest.raises(StorageError):
        runner.call(lambda: 1, 1.0)


def test_deadline_runner_propagates_errors():
    runner = DeadlineRunner(max_workers=1)

    def boom():
        raise ObjectNotFound("nf", provider="p")
    with pytest.raises(ObjectNotFound):
        runner.call(boom, 1.0)
    runner.shutdown()
