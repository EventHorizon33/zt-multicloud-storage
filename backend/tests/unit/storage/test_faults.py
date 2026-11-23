import pytest

from app.contracts import ObjectNotFound, ProviderTimeout, ProviderUnavailable
from app.storage import FaultInjectingProvider
from app.storage.faults import is_injected
from app.storage.memory import MemoryProvider


@pytest.fixture
def fp():
    sleeps = []
    p = FaultInjectingProvider(MemoryProvider("m"), sleep=sleeps.append)
    p.sleeps = sleeps
    p.put("k", b"hello world")
    return p


def test_status_marks_injection(fp):
    assert fp.status()["injected"] is False and fp.status()["fault_injection_enabled"] is True
    st = fp.set_mode("unavailable")
    assert st["injected"] is True and st["mode"] == "unavailable"


def test_unavailable(fp):
    fp.set_mode("unavailable")
    for call in (lambda: fp.get("k"), lambda: fp.put("k", b"x"), lambda: fp.delete("k"),
                 lambda: fp.exists("k"), lambda: fp.stat("k"), lambda: fp.list_keys("")):
        with pytest.raises(ProviderUnavailable) as ei:
            call()
        assert is_injected(ei.value) and "injected fault" in str(ei.value)
    h = fp.health()
    assert h.healthy is False and "injected" in h.error
    fp.clear()
    assert fp.get("k") == b"hello world"


def test_timeout_with_delay(fp):
    fp.set_mode("timeout", delay=0.3)
    with pytest.raises(ProviderTimeout) as ei:
        fp.get("k")
    assert is_injected(ei.value)
    assert fp.sleeps == [0.3]
    assert fp.health().healthy is False


def test_corrupt_reads(fp):
    fp.set_mode("corrupt-reads")
    got = fp.get("k")
    assert got != b"hello world" and len(got) == len(b"hello world")
    fp.put("e", b"")
    assert fp.get("e") != b""
    fp.clear()
    assert fp.get("k") == b"hello world"  # stored data never touched


def test_fail_n_then_recover(fp):
    fp.set_mode("fail-n", n=2)
    assert fp.health().healthy  # probes do not consume the budget
    for _ in range(2):
        with pytest.raises(ProviderUnavailable):
            fp.get("k")
    assert fp.get("k") == b"hello world"
    assert fp.status()["injected"] is False and fp.status()["injected_failures_total"] == 2


def test_drop_writes_lies(fp):
    fp.set_mode("drop-writes")
    info = fp.put("new", b"abc")
    assert info.size == 3
    with pytest.raises(ObjectNotFound):
        fp.get("new")


def test_slow(fp):
    fp.set_mode("slow", delay=0.2)
    assert fp.get("k") == b"hello world"
    assert fp.sleeps == [0.2]


def test_invalid_modes_and_params(fp):
    with pytest.raises(ValueError):
        fp.set_mode("explode")
    with pytest.raises(ValueError):
        fp.set_mode("unavailable", n=3)
    with pytest.raises(ValueError):
        fp.set_mode("slow", delay=-1)
    with pytest.raises(ValueError):
        fp.set_mode("fail-n", n=-1)
