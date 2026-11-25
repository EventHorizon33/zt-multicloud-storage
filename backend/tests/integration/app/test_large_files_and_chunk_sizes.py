"""Behaviour that the large-file deployment settings rely on.

* A single download larger than the detector's whole byte budget is refused (and the user is
  blocked), because the check is ``bytes so far + this file > threshold``. This is why a deployment
  that serves large files must raise ``detect_max_download_bytes_in_window`` (deploy/README.md).
* With the threshold at twice the file size (the ratio the deployment uses: 20 GiB for files of up
  to 10 GiB) two downloads pass and the third is blocked.
* Files written under one chunk size stay readable and verifiable after the chunk size setting
  changes, because every file's manifest records its own chunk size.
"""
from __future__ import annotations

import hashlib
import os

from app.storage import FaultInjectingProvider
from app.storage.memory import MemoryProvider

from .conftest import PROVIDERS, build_env


def test_a_single_download_above_the_whole_byte_budget_is_blocked(make_env):
    env = make_env(detect_max_download_bytes_in_window=10_000)
    alice = env.user("alice")
    big = env.upload_ok(alice, os.urandom(16_000))                 # one file larger than the whole window budget
    r = env.download(alice, big["id"])
    assert r.status_code == 403 and r.json()["reasons"] == ["download-rate-exceeded"]
    alerts = env.audit_events(event_type="security.anomaly.bulk-download")
    assert len(alerts) == 1
    assert (alerts[0]["severity"], alerts[0]["reason"]) == ("critical", "download-bytes-threshold")
    # the block is per user and covers every download, not just the big file
    small = env.upload_ok(alice, os.urandom(100))
    assert env.download(alice, small["id"]).status_code == 403


def test_threshold_of_twice_the_file_size_allows_two_downloads_and_blocks_the_third(make_env):
    size = 6_000
    env = make_env(detect_max_download_bytes_in_window=2 * size)
    alice = env.user("alice")
    f = env.upload_ok(alice, os.urandom(size))
    codes = [env.download(alice, f["id"]).status_code for _ in range(3)]
    assert codes == [200, 200, 403]


def test_a_file_of_exactly_the_threshold_size_can_be_downloaded_once(make_env):
    size = 6_000
    env = make_env(detect_max_download_bytes_in_window=size)
    alice = env.user("alice")
    f = env.upload_ok(alice, os.urandom(size))
    assert [env.download(alice, f["id"]).status_code for _ in range(2)] == [200, 403]


def test_files_written_under_another_chunk_size_stay_readable_and_verifiable(tmp_path):
    providers = {n: FaultInjectingProvider(MemoryProvider(n), sleep=lambda s: None) for n in PROVIDERS}
    old_data = os.urandom(10_000)
    new_data = os.urandom(40_000)

    env1, client1 = build_env(tmp_path, providers=providers, chunk_size_bytes=4096)      # the "old deployment"
    with client1:
        t1 = env1.user("alice")
        old = env1.upload_ok(t1, old_data, filename="old.bin")
    assert (old["chunk_size"], old["chunk_count"]) == (4096, 3)

    env2, client2 = build_env(tmp_path, providers=providers, chunk_size_bytes=16_384)    # same database, new setting
    with client2:
        t2 = env2.login("alice")
        r = env2.download(t2, old["id"])
        assert r.status_code == 200 and r.content == old_data
        assert r.headers["x-content-sha256"] == hashlib.sha256(old_data).hexdigest()
        v = env2.client.post(f"/api/files/{old['id']}/verify", headers=env2.h(t2))
        assert v.status_code == 200 and v.json()["healthy"] is True

        new = env2.upload_ok(t2, new_data, filename="new.bin")
        assert (new["chunk_size"], new["chunk_count"]) == (16_384, 3)
        r = env2.download(t2, new["id"])
        assert r.status_code == 200 and r.content == new_data
        # both files are listed with the chunk size they were written with
        sizes = {f["id"]: f["chunk_size"] for f in env2.client.get("/api/files", headers=env2.h(t2)).json()["files"]
                 if "chunk_size" in f}
        assert sizes.get(old["id"], 4096) == 4096 and sizes.get(new["id"], 16_384) == 16_384
