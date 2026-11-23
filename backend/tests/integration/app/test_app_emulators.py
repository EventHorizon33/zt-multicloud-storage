"""Full application flow through the REAL S3 / Azure Blob / GCS adapters
against local EMULATORS (moto server, Azurite, gcp-storage-emulator).

This proves the integrated app works with the real vendor SDKs against those
emulators; it does not prove behaviour against real AWS/Azure/GCP.
Skips (with the reason) when an emulator is not reachable."""
from __future__ import annotations

import hashlib
import os
import socket
import uuid
from urllib.parse import urlparse

import pytest

from app.storage import build_providers

from .conftest import build_env

pytestmark = pytest.mark.emulator

S3_URL = os.environ.get("ZT_S3_ENDPOINT_URL", "http://127.0.0.1:5001")
GCS_URL = os.environ.get("ZT_GCS_ENDPOINT_URL", "http://127.0.0.1:9023")
AZURITE_CONN = os.environ.get(
    "ZT_AZURE_CONNECTION_STRING",
    # Azurite's public, documented development account (not a secret)
    "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;"
    "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
    "BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;")
# A private bucket per test run by default (finding F4): never share the
# deployment default "zt-chunks" with other deployments using the same
# emulators. Set ZT_EMU_BUCKET to pin a name.
BUCKET = os.environ.get("ZT_EMU_BUCKET") or "zt-it-" + uuid.uuid4().hex[:10]


def _reachable(url: str) -> bool:
    u = urlparse(url)
    try:
        with socket.create_connection((u.hostname, u.port or 80), timeout=1):
            return True
    except OSError:
        return False


def _azure_url() -> str:
    for part in AZURITE_CONN.split(";"):
        if part.startswith("BlobEndpoint="):
            return part.split("=", 1)[1]
    return "http://127.0.0.1:10000"


@pytest.fixture
def emu_env(tmp_path):
    for label, url in (("moto S3", S3_URL), ("Azurite blob", _azure_url()), ("gcp-storage-emulator", GCS_URL)):
        if not _reachable(url):
            pytest.skip(f"{label} emulator not reachable at {url} (run scripts/emulators.sh start)")
    overrides = dict(storage_providers="aws-s3,azure-blob,gcs", s3_endpoint_url=S3_URL, s3_bucket=BUCKET,
                     s3_access_key_id="test", s3_secret_access_key="test", azure_connection_string=AZURITE_CONN,
                     azure_container=BUCKET, gcs_endpoint_url=GCS_URL, gcs_bucket=BUCKET, gcs_project="zt-local",
                     chunk_size_bytes=64 * 1024, enable_fault_injection=False)
    from app.config import Settings as S
    settings = S(_env_file=None, env="test", data_dir=tmp_path, **overrides)
    providers = build_providers(settings, enable_fault_injection=False)
    for p in providers.values():
        p.ensure_bucket()
        st = p.health()
        if not st.healthy:
            pytest.skip(f"{p.name} emulator unhealthy: {st.error}")
    env, client = build_env(tmp_path / "app", providers=providers, **overrides)
    client.__enter__()
    yield env
    client.__exit__(None, None, None)
    if not os.environ.get("ZT_EMU_BUCKET"):        # the bucket is ours: remove every object (chunks + anchors)
        for p in providers.values():
            try:
                for key in list(p.list_keys("")):
                    p.delete(key)
            except Exception:
                pass


def test_full_flow_through_three_real_adapters(emu_env):
    env = emu_env
    token = env.user("alice")
    marker = b"EMULATOR-PLAINTEXT-MARKER-"
    data = (marker + os.urandom(997)) * 400                     # ~410 KiB -> 7 chunks of 64 KiB
    meta = env.upload_ok(token, data, filename="emulator-test.bin")
    assert meta["chunk_count"] == 7

    dist = env.client.get(f"/api/files/{meta['id']}/distribution", headers=env.h(token)).json()
    per_provider = {name: 0 for name in ("aws-s3", "azure-blob", "gcs")}
    for chunk in dist["chunks"]:
        assert len(chunk["replicas"]) == 2
        for rep in chunk["replicas"]:
            provider = env.providers[rep["provider"]]
            assert provider.exists(chunk["chunk_id"]), (rep["provider"], chunk["chunk_id"])
            blob = provider.get(chunk["chunk_id"])                 # read back through the real SDK
            assert hashlib.sha256(blob).hexdigest() == chunk["ciphertext_sha256"]
            assert marker not in blob and b"emulator-test" not in blob
            per_provider[rep["provider"]] += 1
    assert all(n > 0 for n in per_provider.values()), per_provider   # all three clouds hold chunks
    assert sum(per_provider.values()) == 14

    r = env.download(token, meta["id"])
    assert r.status_code == 200 and hashlib.sha256(r.content).digest() == hashlib.sha256(data).digest()

    secret = env.enable_mfa(token)
    r = env.client.delete(f"/api/files/{meta['id']}", headers=env.h(token))
    assert r.status_code == 200 and r.json()["leftover_replicas"] == 0
    for chunk in dist["chunks"]:
        for rep in chunk["replicas"]:
            assert not env.providers[rep["provider"]].exists(chunk["chunk_id"])
    report = env.container.audit.verify_chain()
    assert report.ok, report.to_dict()
    del secret
