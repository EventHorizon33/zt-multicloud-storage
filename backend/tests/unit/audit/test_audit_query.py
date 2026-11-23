"""Search, stats, security feed."""
from __future__ import annotations

from datetime import timedelta

import pytest


@pytest.fixture
def populated(service, clock):
    s = service
    s.record(event_type="auth.login", action="auth:login", outcome="success", actor_id="alice",
             request_id="r1")                                                    # 1
    s.record(event_type="auth.login", action="auth:login", outcome="failure", actor_id="bob",
             severity="warning", reason="bad-password")                         # 2
    s.record(event_type="auth.mfa", action="auth:mfa", outcome="success", actor_id="alice") # 3
    clock.advance(timedelta(hours=1))
    s.record(event_type="file.upload", action="file:create", outcome="success",
             actor_id="alice", resource_type="file", resource_id="f1")          # 4
    s.record(event_type="file.download", action="file:read", outcome="denied",
             actor_id="bob", resource_type="file", resource_id="f1")            # 5
    s.record(event_type="file.download", action="file:read", outcome="failure",
             actor_id="alice", resource_type="file", resource_id="f2",
             severity="critical", reason="integrity-failure")                   # 6
    s.record(event_type="authz.decision", action="file:read", outcome="error",
             resource_type="file", resource_id="f2", request_id="r2")           # 7
    return s


def _seqs(events):
    return [e["seq"] for e in events]


def test_each_filter(populated, clock):
    s = populated
    alice = s.pseudonym_for("alice")
    assert _seqs(s.search(actor=alice)[0]) == [6, 4, 3, 1]
    assert _seqs(s.search(event_type="auth.login")[0]) == [2, 1]
    assert _seqs(s.search(event_type="auth.*")[0]) == [3, 2, 1]
    assert _seqs(s.search(event_type="auth.")[0]) == [3, 2, 1]
    assert _seqs(s.search(event_type="auth*")[0]) == [7, 3, 2, 1]   # raw prefix incl. "authz"
    assert _seqs(s.search(action="file:read")[0]) == [7, 6, 5]
    assert _seqs(s.search(resource_id="f1")[0]) == [5, 4]
    assert _seqs(s.search(resource_type="file")[0]) == [7, 6, 5, 4]
    assert _seqs(s.search(outcome="denied")[0]) == [5]
    assert _seqs(s.search(severity="warning")[0]) == [2]
    assert _seqs(s.search(min_severity="warning")[0]) == [6, 2]
    assert _seqs(s.search(request_id="r2")[0]) == [7]
    t4 = s.get_event(4)["ts"]
    assert _seqs(s.search(ts_from=t4)[0]) == [7, 6, 5, 4]
    assert _seqs(s.search(ts_to=t4)[0]) == [3, 2, 1]


def test_filter_combinations_and_order(populated):
    s = populated
    events, total = s.search(actor=s.pseudonym_for("alice"), event_type="file.*",
                             order="asc")
    assert _seqs(events) == [4, 6] and total == 2
    events, total = s.search(outcome="failure", resource_type="file")
    assert _seqs(events) == [6] and total == 1


def test_pagination_and_total(populated):
    s = populated
    page1, total = s.search(limit=3)
    page2, _ = s.search(limit=3, offset=3)
    page3, _ = s.search(limit=3, offset=6)
    assert total == 7
    assert _seqs(page1) == [7, 6, 5] and _seqs(page2) == [4, 3, 2] and _seqs(page3) == [1]
    assert s.search(limit=3, offset=100) == ([], 7)


@pytest.mark.parametrize("kw", [{"limit": 0}, {"limit": 1001}, {"limit": -1}, {"offset": -1},
                                {"order": "sideways"}, {"limit": "10"}, {"min_severity": "x"}])
def test_bounds(populated, kw):
    with pytest.raises(ValueError):
        populated.search(**kw)


def test_limit_max_allowed(populated):
    assert populated.search(limit=1000)[1] == 7


def test_injection_strings_are_just_values(populated):
    assert populated.search(actor="x' OR '1'='1") == ([], 0)
    assert populated.search(event_type="%") == ([], 0)
    assert populated.search(event_type="%*") == ([], 0)          # LIKE wildcards escaped
    assert populated.search(event_type="file_*") == ([], 0)


def test_events_carry_integrity_fields(populated):
    ev = populated.get_event(5)
    assert {"seq", "hash", "prev_hash", "details", "actor", "ts"} <= set(ev)
    assert ev["prev_hash"] == populated.get_event(4)["hash"]
    assert populated.get_event(999) is None


def test_stats(populated):
    st = populated.stats()
    assert st["total"] == 7
    assert st["by_outcome"] == {"success": 3, "failure": 2, "denied": 1, "error": 1}
    assert st["by_severity"] == {"info": 5, "warning": 1, "critical": 1}
    assert st["by_event_prefix"] == {"auth": 3, "authz": 1, "file": 3}
    assert st["by_event_type"]["file.download"] == 2
    assert (st["first_seq"], st["last_seq"]) == (1, 7)
    since = populated.stats(populated.get_event(4)["ts"])
    assert since["total"] == 4 and since["by_outcome"]["success"] == 1


def test_recent_security_events(populated):
    evs = populated.recent_security_events(limit=10)
    assert _seqs(evs) == [6, 5, 2]
    assert _seqs(populated.recent_security_events(limit=1)) == [6]
    with pytest.raises(ValueError):
        populated.recent_security_events(limit=0)
