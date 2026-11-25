"""The container deployment files must agree with each other and with the application's settings.

Nothing here builds or runs Docker or nginx (that has never been done, see deploy/README.md). These
tests only check the relationships that must hold between docker-compose.yml, nginx.conf and
app.config.Settings, so a later edit of one file cannot silently break another.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.config import Settings
from app.cryptoengine.chunks import MAX_CHUNK_SIZE

MIB, GIB = 1024 * 1024, 1024 ** 3
DEPLOY = Path(__file__).resolve().parents[4] / "deploy"


def backend_env() -> dict[str, str]:
    """ZT_* values of the backend service in docker-compose.yml (text parse; no YAML dependency)."""
    text = (DEPLOY / "docker-compose.yml").read_text(encoding="utf-8")
    block = text.split("\n  backend:\n", 1)[1].split("\n  frontend:\n", 1)[0]
    return {m.group(1): m.group(2) for m in re.finditer(r'^\s+(ZT_[A-Z0-9_]+):\s*"([^"]*)"', block, re.M)}


def nginx_directive(name: str) -> str:
    text = re.sub(r"#.*", "", (DEPLOY / "nginx.conf").read_text(encoding="utf-8"))
    m = re.search(rf"^\s*{name}\s+([^;]+);", text, re.M)
    assert m, f"{name} not set in nginx.conf"
    return m.group(1).strip()


TUNING_KEYS = ("ZT_CHUNK_SIZE_BYTES", "ZT_STORAGE_TIMEOUT_SECONDS", "ZT_MAX_UPLOAD_BYTES",
               "ZT_DETECT_MAX_DOWNLOAD_BYTES_IN_WINDOW")


def settings_from(env: dict[str, str], tmp_path, monkeypatch) -> Settings:
    """Load the tuning values the way a real deployment does: as ZT_* environment variables."""
    for key in TUNING_KEYS:
        assert key in env, f"{key} missing from the backend service in docker-compose.yml"
        monkeypatch.setenv(key, env[key])
    return Settings(_env_file=None, env="test", data_dir=tmp_path, storage_providers="memory-a,memory-b,memory-c")


def test_compose_values_are_accepted_by_the_application_settings(tmp_path, monkeypatch):
    s = settings_from(backend_env(), tmp_path, monkeypatch)
    assert s.chunk_size_bytes == 16 * MIB
    assert s.storage_timeout_seconds == 30.0
    assert s.max_upload_bytes == 10 * GIB
    assert s.detect_max_download_bytes_in_window == 20 * GIB
    assert MIB <= s.chunk_size_bytes <= MAX_CHUNK_SIZE


def test_the_detector_budget_admits_at_least_one_maximum_size_download(tmp_path, monkeypatch):
    s = settings_from(backend_env(), tmp_path, monkeypatch)
    # a file at the upload cap is refused if its size alone exceeds the whole window budget
    assert s.detect_max_download_bytes_in_window >= s.max_upload_bytes
    # and the budget stays a real limit: it is a small multiple of the largest file, not unlimited
    assert s.detect_max_download_bytes_in_window <= 4 * s.max_upload_bytes


def test_nginx_admits_the_backend_upload_cap_plus_multipart_overhead(tmp_path, monkeypatch):
    s = settings_from(backend_env(), tmp_path, monkeypatch)
    limit = nginx_directive("client_max_body_size")
    assert limit.endswith("m"), "expected a size in MiB, e.g. 10250m"
    assert int(limit[:-1]) * MIB > s.max_upload_bytes + MIB      # the backend itself allows cap + 1 MiB


def test_nginx_does_not_buffer_uploads_and_waits_long_enough_for_verify_then_release():
    assert nginx_directive("proxy_request_buffering") == "off"
    # the backend sends nothing until the whole file is fetched and verified (55 s for 10 GiB on local emulators)
    assert int(nginx_directive("proxy_read_timeout").rstrip("s")) >= 600


def test_the_provider_deadline_is_long_enough_for_one_chunk_at_a_modest_rate(tmp_path, monkeypatch):
    s = settings_from(backend_env(), tmp_path, monkeypatch)
    min_rate_mib_s = (s.chunk_size_bytes / MIB) / s.storage_timeout_seconds
    assert min_rate_mib_s <= 1.0, f"one chunk needs {min_rate_mib_s:.2f} MiB/s per replica to meet the deadline"


def test_framework_defaults_are_unchanged_by_the_deployment_overrides():
    f = Settings.model_fields
    assert f["chunk_size_bytes"].default == 1 * MIB            # tests, the demo and the paper assume this
    assert f["max_upload_bytes"].default == 256 * MIB
    assert f["detect_max_download_bytes_in_window"].default == 512 * MIB
    assert f["storage_timeout_seconds"].default == 10.0


@pytest.mark.parametrize("name", ["ZT_ENV", "ZT_ENABLE_FAULT_INJECTION"])
def test_the_deployment_keeps_production_safety_settings(name):
    expected = {"ZT_ENV": "production", "ZT_ENABLE_FAULT_INJECTION": "false"}[name]
    assert backend_env()[name] == expected
