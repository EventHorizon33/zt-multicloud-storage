"""Emulator-backed fixtures. Each fixture SKIPS (with the reason) when its
emulator is not reachable; start them with ``scripts/emulators.sh start``.

These tests exercise the real boto3 / azure-storage-blob /
google-cloud-storage SDKs against local EMULATORS (moto, Azurite,
gcp-storage-emulator), not against AWS, Azure or GCP."""
from __future__ import annotations

import os
import socket
import uuid
from pathlib import Path
from urllib.parse import urlparse

import pytest

from app.storage.azure import AzureBlobProvider
from app.storage.gcs import GCSProvider
from app.storage.s3 import S3Provider

REPO = Path(__file__).resolve().parents[4]
EMULATORS_SH = REPO / "scripts" / "emulators.sh"

S3_URL = os.environ.get("ZT_S3_ENDPOINT_URL", "http://127.0.0.1:5001")
GCS_URL = os.environ.get("ZT_GCS_ENDPOINT_URL", "http://127.0.0.1:9023")
# Azurite's public, documented development account (not a secret).
AZURITE_CONN = os.environ.get(
    "ZT_AZURE_CONNECTION_STRING",
    "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;"
    "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
    "BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;")
# A private bucket per test run by default (finding F4): never share the
# deployment default "zt-chunks" with other deployments using the same
# emulators. Set ZT_EMU_BUCKET to pin a name.
BUCKET = os.environ.get("ZT_EMU_BUCKET") or "zt-it-" + uuid.uuid4().hex[:10]


def _azure_url() -> str:
    for part in AZURITE_CONN.split(";"):
        if part.startswith("BlobEndpoint="):
            return part.split("=", 1)[1]
    return "http://127.0.0.1:10000"


def _reachable(url: str) -> bool:
    u = urlparse(url)
    try:
        with socket.create_connection((u.hostname, u.port or 80), timeout=1):
            return True
    except OSError:
        return False


def _ready(provider, label: str, url: str):
    if not _reachable(url):
        pytest.skip(f"{label} emulator not reachable at {url} (run scripts/emulators.sh start)")
    provider.ensure_bucket()
    st = provider.health()
    if not st.healthy:
        pytest.skip(f"{label} emulator at {url} answered but is unhealthy: {st.error}")
    return provider


def make_s3() -> S3Provider:
    return S3Provider(bucket=BUCKET, endpoint_url=S3_URL, access_key_id="test", secret_access_key="test",
                      timeout_seconds=5)


def make_azure() -> AzureBlobProvider:
    return AzureBlobProvider(connection_string=AZURITE_CONN, container=BUCKET, timeout_seconds=5)


def make_gcs() -> GCSProvider:
    return GCSProvider(bucket=BUCKET, endpoint_url=GCS_URL, project="zt-local", timeout_seconds=5)


@pytest.fixture
def s3_provider():
    return _ready(make_s3(), "moto S3", S3_URL)


@pytest.fixture
def azure_provider():
    return _ready(make_azure(), "Azurite blob", _azure_url())


@pytest.fixture
def gcs_provider():
    return _ready(make_gcs(), "gcp-storage-emulator", GCS_URL)


@pytest.fixture
def all_providers(s3_provider, azure_provider, gcs_provider):
    return {p.name: p for p in (s3_provider, azure_provider, gcs_provider)}
