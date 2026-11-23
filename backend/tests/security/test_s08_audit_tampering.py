"""Scenario 8: an attacker with write access to the AUDIT database edits the
trail to hide an intrusion (direct SQL, bypassing the application).

Mechanisms (ADR-0006): SHA-256 hash chain over every record, Ed25519-signed
checkpoints (signing key in the KMS, not in the audit DB), checkpoint anchors
on every storage provider, verification endpoint ``POST /api/audit/verify``
(auditor/admin), which is itself audited (``audit.verify``)."""
from __future__ import annotations

import pytest

from .conftest import payload

pytestmark = pytest.mark.security


def _intrusion(env) -> tuple[str, str, dict]:
    """mallory probes alice's file; returns (auditor token, mallory pseudonym, the deny event)."""
    alice = env.user("alice")
    mallory = env.user("mallory")
    meta = env.upload_ok(alice, payload())
    r = env.req("GET", f"/api/files/{meta['id']}/download", mallory)
    assert r.status_code == 404
    deny = env.one(r, "authz.decision")
    auditor = env.auditor()
    for _ in range(3):                                   # some later, unrelated activity
        env.client.get("/api/files", headers=env.h(alice))
    return auditor, env.me(mallory)["audit_pseudonym"], deny


def _verify(env, auditor, evidence_obj=None):
    r = env.req("POST", "/api/audit/verify", auditor, json={})
    assert r.status_code == 200, r.text
    rep = r.json()
    audit_ev = env.one(r, "audit.verify")
    return rep, audit_ev, r


def _types(rep) -> set[str]:
    return {f["type"] for f in rep["findings"]}


def test_s08_baseline_chain_verifies(env, evidence):
    ev = evidence("S08", "(baseline) verify an untampered audit log", "hash chain + signed, anchored checkpoints")
    auditor, _, _ = _intrusion(env)
    admin, _ = env.admin()
    assert env.client.post("/api/audit/checkpoints", headers=env.h(admin)).status_code == 201
    rep, a, r = _verify(env, auditor)
    assert rep["ok"] is True and rep["findings"] == [] and rep["anchors_checked"] >= 3
    assert (a["outcome"], a["severity"], a["actor_role"]) == ("success", "info", "auditor")
    ev.result(f"ok=true events_checked={rep['events_checked']} anchors_checked={rep['anchors_checked']}")
    ev.audit(a)


def test_s08_modified_record(env, evidence):
    ev = evidence("S08", "UPDATE the attacker's 'denied' authz record to outcome='success'",
                  "Record hash recomputed by the verifier != stored hash")
    auditor, _, deny = _intrusion(env)
    env.audit_sql().execute("UPDATE audit_events SET outcome='success', severity='info' WHERE seq=?",
                            (deny["seq"],))
    rep, a, r = _verify(env, auditor)
    assert rep["ok"] is False and "record-modified" in _types(rep)
    assert any(f["seq"] == deny["seq"] and f["type"] == "record-modified" for f in rep["findings"])
    assert (a["outcome"], a["severity"]) == ("failure", "critical")
    assert "record-modified" in a["details"]["finding_types"]
    # retention refuses to launder a tampered chain (once the tampered record is old enough to be pruned)
    env.clock.advance((env.settings.audit_retention_days + 1) * 86400)
    admin, _ = env.admin()
    rr = env.req("POST", "/api/audit/retention", admin)
    assert rr.status_code == 409 and rr.json()["error"] == "audit-integrity-failure", rr.text
    ev.result(f"ok=false findings={sorted(_types(rep))}; retention -> 409")
    ev.audit(a)


def test_s08_modified_record_with_recomputed_hash(env, evidence):
    ev = evidence("S08", "UPDATE a record AND recompute its own hash (attacker knows the formula)",
                  "Next record's prev_hash no longer links; signed checkpoint head mismatch")
    import hashlib
    import json as _json

    auditor, _, deny = _intrusion(env)
    db = env.audit_sql()
    cols = [c[1] for c in db.execute("PRAGMA table_info(audit_events)")]
    row = dict(zip(cols, db.execute("SELECT * FROM audit_events WHERE seq=?", (deny["seq"],)).fetchone()))
    row["outcome"], row["severity"] = "success", "info"
    body = {k: v for k, v in row.items() if k != "hash"}
    new_hash = hashlib.sha256(bytes.fromhex(row["prev_hash"]) + _json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
    db.execute("UPDATE audit_events SET outcome='success', severity='info', hash=? WHERE seq=?",
               (new_hash, deny["seq"]))
    rep, a, _ = _verify(env, auditor)
    assert rep["ok"] is False and "chain-broken" in _types(rep)
    assert "record-modified" not in {f["type"] for f in rep["findings"] if f["seq"] == deny["seq"]}
    assert a["severity"] == "critical"
    ev.result(f"ok=false findings={sorted(_types(rep))}")
    ev.audit(a)


def test_s08_deleted_record(env, evidence):
    ev = evidence("S08", "DELETE the attacker's 'denied' authz record", "Sequence gap + broken prev_hash link")
    auditor, _, deny = _intrusion(env)
    env.audit_sql().execute("DELETE FROM audit_events WHERE seq=?", (deny["seq"],))
    rep, a, _ = _verify(env, auditor)
    assert rep["ok"] is False and {"sequence-gap", "chain-broken"} <= _types(rep)
    assert "sequence-gap" in a["details"]["finding_types"] and a["severity"] == "critical"
    ev.result(f"ok=false findings={sorted(_types(rep))}")
    ev.audit(a)


def test_s08_reordered_records(env, evidence):
    ev = evidence("S08", "Swap two records' positions (seq numbers)", "Chain link points at a record elsewhere")
    auditor, _, deny = _intrusion(env)
    s = deny["seq"]
    db = env.audit_sql()
    db.execute("UPDATE audit_events SET seq=-1 WHERE seq=?", (s,))
    db.execute("UPDATE audit_events SET seq=? WHERE seq=?", (s, s + 1))
    db.execute("UPDATE audit_events SET seq=? WHERE seq=-1", (s + 1,))
    rep, a, _ = _verify(env, auditor)
    assert rep["ok"] is False and "reordered" in _types(rep)
    assert "reordered" in a["details"]["finding_types"]
    ev.result(f"ok=false findings={sorted(_types(rep))}")
    ev.audit(a)


def test_s08_truncated_tail_after_checkpoint(env, evidence):
    ev = evidence("S08", "Delete the newest records (incl. ones covered by a signed checkpoint)",
                  "Signed checkpoint (DB + provider anchors) references a seq beyond the head")
    auditor, _, deny = _intrusion(env)
    admin, _ = env.admin()
    cp = env.client.post("/api/audit/checkpoints", headers=env.h(admin)).json()
    assert all(cp["anchors"].values())
    env.audit_sql().execute("DELETE FROM audit_events WHERE seq>=?", (deny["seq"],))
    rep, a, _ = _verify(env, auditor)
    assert rep["ok"] is False and "truncated" in _types(rep)
    ev.result(f"ok=false findings={sorted(_types(rep))}")
    ev.audit(a)


def test_s08_truncated_tail_and_checkpoint_rows_detected_via_anchors(env, evidence):
    ev = evidence("S08", "Delete the tail AND every checkpoint row in the audit DB",
                  "Checkpoint anchors on the storage providers (outside the audit DB)")
    auditor, _, deny = _intrusion(env)
    admin, _ = env.admin()
    assert env.client.post("/api/audit/checkpoints", headers=env.h(admin)).status_code == 201
    db = env.audit_sql()
    db.execute("DELETE FROM audit_events WHERE seq>=?", (deny["seq"],))
    db.execute("DELETE FROM audit_checkpoints")
    rep, a, _ = _verify(env, auditor)
    assert rep["ok"] is False and "truncated" in _types(rep)
    ev.result(f"ok=false findings={sorted(_types(rep))}")
    ev.audit(a)


def test_s08_forged_checkpoint_signature(env, evidence):
    ev = evidence("S08", "Edit a checkpoint row (head_hash) to match a rewritten log",
                  "Ed25519 signature (key in KMS) no longer verifies")
    auditor, _, _ = _intrusion(env)
    admin, _ = env.admin()
    cp = env.client.post("/api/audit/checkpoints", headers=env.h(admin)).json()
    env.audit_sql().execute("UPDATE audit_checkpoints SET head_hash=? WHERE id=?", ("ab" * 32, cp["id"]))
    rep, a, _ = _verify(env, auditor)
    assert rep["ok"] is False and "checkpoint-signature-invalid" in _types(rep)
    ev.result(f"ok=false findings={sorted(_types(rep))}")
    ev.audit(a)


def test_s08_no_api_path_edits_audit_records(env, evidence):
    ev = evidence("S08", "Admin tries to edit/delete audit records through the API",
                  "No mutating audit routes exist (only verify/checkpoint/retention)")
    auditor, _, deny = _intrusion(env)
    admin, _ = env.admin()
    for method in ("PUT", "PATCH", "DELETE"):
        r = env.req(method, f"/api/audit/events/{deny['seq']}", admin, json={"outcome": "success"})
        assert r.status_code == 405, (method, r.status_code)
    rep, a, _ = _verify(env, auditor)
    assert rep["ok"] is True
    ev.response(r, "DELETE /api/audit/events/{seq}")
    ev.audit(a)


def test_s08_stated_limit_tail_after_last_checkpoint(env, evidence):
    """ADR-0006 stated limit, demonstrated: records newer than the last checkpoint can
    be truncated undetected until the next checkpoint (window = audit_checkpoint_every)."""
    ev = evidence("S08", "(stated limit) delete records written AFTER the last checkpoint",
                  "none until the next checkpoint (window = audit_checkpoint_every events)")
    auditor, _, _ = _intrusion(env)
    admin, _ = env.admin()
    cp = env.client.post("/api/audit/checkpoints", headers=env.h(admin)).json()
    mallory = env.login("mallory")
    env.req("GET", "/api/files/" + "ab" * 16, mallory)          # a deny after the checkpoint
    last = env.audit_sql().execute("SELECT MAX(seq) FROM audit_events").fetchone()[0]
    assert last > cp["seq"]
    env.audit_sql().execute("DELETE FROM audit_events WHERE seq>?", (cp["seq"],))
    rep, a, _ = _verify(env, auditor)
    assert rep["ok"] is True                                    # not detected: the documented limit
    ev.result(f"ok=true (undetected) - {last - cp['seq']} records after checkpoint seq {cp['seq']} removed")
    ev.audit(a)


def test_s08_anchors_of_two_deployments_sharing_a_bucket_do_not_collide(make_env, evidence):
    ev = evidence("S08", "Two deployments (different keystores) write checkpoints at the same seq into one shared bucket",
                  "Anchors namespaced per audit log: anchors/audit/<log_id>/checkpoint-<seq> (F4, ADR-0006 amendment); "
                  "verification reads only its own namespace")
    from tests.integration.app.conftest import PROVIDERS
    from app.storage import FaultInjectingProvider
    from app.storage.memory import MemoryProvider

    shared = {n: FaultInjectingProvider(MemoryProvider(n), sleep=lambda s: None) for n in PROVIDERS}
    a = make_env(providers=shared, audit_checkpoint_every=20)
    b = make_env(providers=shared, audit_checkpoint_every=20)
    for env in (a, b):                                         # both logs pass seq 20 -> periodic checkpoint
        tok = env.user("worker")
        for _ in range(25):
            env.client.get("/api/files/" + "ab" * 16, headers=env.h(tok))
    rep = a.container.audit.verify_chain()
    assert rep.ok, [f.type for f in rep.findings][:5]
    rep_b = b.container.audit.verify_chain()
    assert rep_b.ok, [f.type for f in rep_b.findings][:5]
    la, lb = a.container.audit.log_id, b.container.audit.log_id
    assert la != lb
    keys = list(shared["memory-a"].inner.list_keys("anchors/audit/"))
    ka = f"anchors/audit/{la}/checkpoint-000000000020.json"
    kb = f"anchors/audit/{lb}/checkpoint-000000000020.json"
    assert ka in keys and kb in keys                            # same seq, two objects, nothing overwritten
    assert rep.anchors_checked > 0 and "anchor-mismatch" not in rep.finding_types()
    ev.result(f"A and B both verify ok=True; seq 20 anchored at {ka} and {kb}")
    ev.result(f"A: {rep.anchors_checked} anchor copies checked, findings={sorted(rep.finding_types())}")
