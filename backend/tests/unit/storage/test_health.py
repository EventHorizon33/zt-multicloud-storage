import time

from app.contracts import Outcome
from app.storage import FaultInjectingProvider, HealthMonitor
from app.storage.memory import MemoryProvider

from .conftest import FakeAudit, FakeClock


def make(threshold=3, cooldown=30.0):
    providers = {n: FaultInjectingProvider(MemoryProvider(n)) for n in ("a", "b")}
    audit, clock = FakeAudit(), FakeClock()
    hm = HealthMonitor(providers, interval=60, clock=clock, failure_threshold=threshold,
                       cooldown_seconds=cooldown, audit=audit)
    return hm, providers, audit, clock


def test_active_probe_and_snapshot():
    hm, providers, audit, _ = make()
    rows = {r["provider"]: r for r in hm.check_all()}
    assert rows["a"]["healthy"] is True and rows["a"]["state"] == "closed"
    assert rows["a"]["latency_ms"] is not None and rows["a"]["last_checked"]
    providers["b"].set_mode("unavailable")
    rows = {r["provider"]: r for r in hm.check_all()}
    assert rows["b"]["healthy"] is False and rows["b"]["injected"] is True
    assert rows["b"]["fault_mode"] == "unavailable" and "injected" in rows["b"]["last_error"]


def test_audit_only_on_transitions():
    hm, providers, audit, _ = make()
    for _ in range(3):
        hm.check_all()
    assert audit.of("storage.provider.health") == [] or all(
        e["outcome"] == Outcome.SUCCESS for e in audit.of("storage.provider.health"))
    first = len(audit.of("storage.provider.health"))   # unknown -> healthy transitions
    assert first == 2
    providers["a"].set_mode("unavailable")
    for _ in range(5):
        hm.check_all()
    ev = audit.of("storage.provider.health")[first:]
    # healthy->unhealthy (closed) and closed->open: two transitions, not five probes
    assert [e["details"]["state"] for e in ev] == ["closed", "open"]
    assert all(e["outcome"] == Outcome.ERROR for e in ev) and all(e["details"]["injected"] for e in ev)
    providers["a"].clear()
    hm.check_all()
    hm.check_all()
    ev = audit.of("storage.provider.health")[first + 2:]
    assert len(ev) == 1 and ev[0]["outcome"] == Outcome.SUCCESS and ev[0]["details"]["state"] == "closed"


def test_circuit_breaker_open_halfopen_close():
    hm, _, _, clock = make(threshold=3, cooldown=30)
    for _ in range(2):
        hm.record_failure("a", "ProviderUnavailable: down")
    assert hm.breaker_state("a") == "closed" and hm.allow_request("a")
    hm.record_failure("a", "ProviderUnavailable: down")
    assert hm.breaker_state("a") == "open" and hm.is_open("a") and hm.rank("a") == 2
    assert hm.allow_request("a") is False
    clock.advance(29)
    assert hm.allow_request("a") is False
    clock.advance(2)
    assert hm.allow_request("a") is True            # half-open trial
    assert hm.breaker_state("a") == "half-open"
    assert hm.allow_request("a") is False           # only one trial at a time
    hm.record_failure("a", "still down")
    assert hm.breaker_state("a") == "open"          # failed trial re-opens
    clock.advance(31)
    assert hm.allow_request("a") is True
    hm.record_success("a", 1.0)
    assert hm.breaker_state("a") == "closed" and hm.rank("a") == 0
    assert hm.snapshot()[0]["consecutive_failures"] == 0


def test_abandoned_trial_is_released_after_cooldown():
    hm, _, _, clock = make(threshold=1, cooldown=10)
    hm.record_failure("a", "x")
    clock.advance(10)
    assert hm.allow_request("a")
    assert not hm.allow_request("a")
    clock.advance(10)
    assert hm.allow_request("a")


def test_success_resets_consecutive_failures():
    hm, _, _, _ = make(threshold=3)
    hm.record_failure("a", "x")
    hm.record_failure("a", "x")
    hm.record_success("a")
    hm.record_failure("a", "x")
    hm.record_failure("a", "x")
    assert hm.breaker_state("a") == "closed"


def test_error_strings_are_sanitised():
    hm, _, audit, _ = make(threshold=1)
    hm.record_failure("a", "failed DefaultEndpointsProtocol=https;AccountName=x;AccountKey=c2VjcmV0c2VjcmV0;"
                           " url https://h/b?X-Amz-Signature=abcdef password=hunter2")
    row = hm.snapshot()[0]
    for secret in ("c2VjcmV0c2VjcmV0", "abcdef", "hunter2", "AccountKey"):
        assert secret not in row["last_error"]
        assert secret not in repr(audit.events)


def test_background_thread_start_stop():
    providers = {"a": MemoryProvider("a")}
    hm = HealthMonitor(providers, interval=0.02)
    hm.start()
    hm.start()  # idempotent
    deadline = time.time() + 2
    while hm.snapshot()[0]["total_successes"] < 2 and time.time() < deadline:
        time.sleep(0.01)
    assert hm.snapshot()[0]["total_successes"] >= 2
    hm.stop()
    assert not hm.running


def test_audit_failure_does_not_break_monitor():
    hm, providers, audit, _ = make()
    audit.fail = True
    providers["a"].set_mode("unavailable")
    hm.check_all()  # must not raise
    assert hm.snapshot()[0]["healthy"] is False
