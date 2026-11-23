import threading

import pytest

from app.errors import RateLimited
from app.ratelimit import RateLimiter


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_limit_and_retry_after():
    c = Clock()
    rl = RateLimiter(clock=c)
    for _ in range(10):
        rl.check("login", "1.2.3.4", 10)
    with pytest.raises(RateLimited) as ei:
        rl.check("login", "1.2.3.4", 10)
    assert ei.value.retry_after_seconds == 6       # 1 token per 6 s
    assert "1.2.3.4" not in str(ei.value)
    rl.check("login", "5.6.7.8", 10)               # other key independent
    rl.check("upload", "1.2.3.4", 10)              # other scope independent


def test_refill():
    c = Clock()
    rl = RateLimiter(clock=c)
    for _ in range(6):
        rl.check("s", "k", 6)                       # 1 token / 10 s
    c.t += 9.9
    with pytest.raises(RateLimited):
        rl.check("s", "k", 6)
    c.t += 0.2
    rl.check("s", "k", 6)
    c.t += 3600
    for _ in range(6):                             # never more than capacity
        rl.check("s", "k", 6)
    with pytest.raises(RateLimited):
        rl.check("s", "k", 6)


def test_invalid_limit():
    with pytest.raises(ValueError):
        RateLimiter().check("s", "k", 0)


def test_idle_buckets_evicted_and_memory_bounded():
    c = Clock()
    rl = RateLimiter(clock=c, max_buckets=100, sweep_every=10)
    for i in range(100):
        rl.check("s", i, 60)
    assert len(rl) == 100
    c.t += 2                                       # all refilled -> idle
    rl.check("s", "new", 60)
    assert len(rl) == 1
    for i in range(500):                            # never idle: LRU bound holds
        rl.check("s", f"k{i}", 60)
    assert len(rl) <= 100


def test_thread_safety():
    rl = RateLimiter(clock=Clock())
    allowed = []
    lock = threading.Lock()

    def worker():
        for _ in range(50):
            try:
                rl.check("s", "shared", 100)
                with lock:
                    allowed.append(1)
            except RateLimited:
                pass

    ts = [threading.Thread(target=worker) for _ in range(8)]
    for t in ts: t.start()
    for t in ts: t.join()
    assert len(allowed) == 100


def test_reset():
    rl = RateLimiter(clock=Clock())
    rl.check("a", 1, 1)
    rl.check("b", 1, 1)
    rl.reset("a")
    rl.check("a", 1, 1)
    with pytest.raises(RateLimited):
        rl.check("b", 1, 1)
