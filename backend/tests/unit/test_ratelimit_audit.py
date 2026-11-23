"""Finding F6: 429s are audited, first per (scope, key) per window, then aggregated."""
from datetime import datetime, timezone

from app.ratelimit import RateLimitAuditor
from tests.unit._fakes_auth import FakeClock, RecordingAudit


def _auditor():
    audit, clock = RecordingAudit(), FakeClock(datetime(2026, 11, 13, tzinfo=timezone.utc))
    return RateLimitAuditor(audit=audit, clock=clock, window_seconds=60, max_keys=3), audit, clock


def test_first_rejection_recorded_then_aggregated():
    a, audit, clock = _auditor()
    a.rejected("login", "198.51.100.7", request_id="req-00000001", source_ip="198.51.100.7")
    for i in range(4):
        a.rejected("login", "198.51.100.7", request_id=f"req-0000001{i}")
    events = audit.of("security.rate-limited")
    assert len(events) == 1
    e = events[0]
    assert e["details"] == {"scope": "login", "count": 1, "window_seconds": 60, "kind": "first"}
    assert e["request_id"] == "req-00000001" and e["severity"].value == "warning"
    assert "198.51.100.7" not in str(e["details"])            # the key never goes into details
    clock.advance(61)
    assert a.flush() == 1
    s = audit.of("security.rate-limited")[-1]
    assert s["details"]["kind"] == "summary" and s["details"]["count"] == 4
    assert s["source_ip"] == "198.51.100.7" and s["request_id"] is None
    assert a.flush() == 0


def test_window_roll_on_next_rejection_emits_summary_then_new_first():
    a, audit, clock = _auditor()
    a.rejected("download", "user-1", user_keyed=True)
    a.rejected("download", "user-1", user_keyed=True)
    clock.advance(60)
    a.rejected("download", "user-1", user_keyed=True)
    kinds = [(e["details"]["kind"], e["details"]["count"], e["actor_id"]) for e in audit.of("security.rate-limited")]
    assert kinds == [("first", 1, "user-1"), ("summary", 1, "user-1"), ("first", 1, "user-1")]


def test_state_is_bounded_and_evicted_windows_are_summarised():
    a, audit, clock = _auditor()                # max_keys=3
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        a.rejected("login", ip)
        a.rejected("login", ip)
    a.rejected("login", "10.0.0.4")             # evicts 10.0.0.1 -> its summary
    summaries = [e for e in audit.of("security.rate-limited") if e["details"]["kind"] == "summary"]
    assert len(summaries) == 1 and summaries[0]["source_ip"] == "10.0.0.1"
    assert a.flush(force=True) == 2
