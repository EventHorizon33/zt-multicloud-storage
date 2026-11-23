import threading

import pytest

from app.storage import StorageMetrics


def test_counters_and_snapshot():
    m = StorageMetrics()
    m.inc("aws-s3", "put", "attempts")
    m.inc("aws-s3", "put", "successes")
    m.inc("aws-s3", "put", "bytes", 1024)
    m.observe("aws-s3", "put", 0.02)
    m.observe("aws-s3", "put", 20.0)
    snap = m.snapshot()
    c = snap["counters"]["aws-s3"]["put"]
    assert c == {"attempts": 1, "successes": 1, "failures": 0, "retries": 0, "bytes": 1024}
    lat = snap["latency"]["aws-s3"]["put"]
    assert lat["count"] == 2 and lat["buckets"]["0.025"] == 1 and lat["buckets"]["+Inf"] == 2
    assert m.total("attempts") == 1 and m.get("aws-s3", "put", "bytes") == 1024
    with pytest.raises(ValueError):
        m.inc("x", "y", "nope")


def test_thread_safety():
    m = StorageMetrics()

    def work():
        for _ in range(2000):
            m.inc("p", "get", "attempts")
    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert m.get("p", "get", "attempts") == 16000


def test_prometheus_rendering():
    m = StorageMetrics()
    m.inc('we"ird', "get", "retries", 3)
    m.observe("p", "get", 0.001)
    text = m.render_prometheus()
    assert '# TYPE zt_storage_retries_total counter' in text
    assert 'zt_storage_retries_total{provider="we\\"ird",op="get"} 3' in text
    assert 'zt_storage_latency_seconds_bucket{provider="p",op="get",le="0.005"} 1' in text
    assert 'zt_storage_latency_seconds_count{provider="p",op="get"} 1' in text
