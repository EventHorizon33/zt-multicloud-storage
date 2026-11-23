"""build_providers + adapter behaviour that needs no running emulator
(construction, configuration errors, sanitisation, connection-refused
translation against a closed localhost port)."""
import pytest

from app.config import Settings
from app.contracts import ProviderAuthError, ProviderUnavailable, StorageError
from app.storage import FaultInjectingProvider, StorageConfigError, build_orchestrator, build_providers
from app.storage._common import sanitize_text, validate_metadata
from app.storage.azure import AzureBlobProvider
from app.storage.gcs import GCSProvider
from app.storage.memory import MemoryProvider
from app.storage.s3 import S3Provider

# Public Azurite development constant (not a secret); used only to build a client.
AZURITE = ("DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;"
           "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
           "BlobEndpoint=http://127.0.0.1:1/devstoreaccount1;")
CLOSED = "http://127.0.0.1:1"


def settings(**kw):
    base = dict(env="test", storage_providers="memory-a,memory-b,memory-c", _env_file=None)
    base.update(kw)
    return Settings(**base)


def test_build_memory_providers_in_test_env():
    ps = build_providers(settings())
    assert list(ps) == ["memory-a", "memory-b", "memory-c"]
    assert all(isinstance(p, MemoryProvider) for p in ps.values())


def test_memory_providers_refused_outside_test():
    with pytest.raises(StorageConfigError, match="only allowed when ZT_ENV=test"):
        build_providers(settings(env="development"))


def test_unknown_and_duplicate_names():
    with pytest.raises(StorageConfigError, match="unknown storage provider"):
        build_providers(settings(storage_providers="aws-s3,dropbox"))
    with pytest.raises(StorageConfigError, match="duplicate"):
        build_providers(settings(storage_providers="memory-a,memory-a"))
    with pytest.raises(StorageConfigError):
        build_providers(settings(storage_providers=" , "))


def test_fault_injection_wrapping_and_production_refusal():
    ps = build_providers(settings(), enable_fault_injection=True)
    assert all(isinstance(p, FaultInjectingProvider) for p in ps.values())
    prod = settings(env="development")
    object.__setattr__(prod, "env", "production")
    with pytest.raises(StorageConfigError):
        build_providers(prod, enable_fault_injection=True)


def test_missing_required_settings_named_not_valued():
    with pytest.raises(StorageConfigError, match="ZT_AZURE_CONNECTION_STRING"):
        build_providers(settings(storage_providers="azure-blob", azure_connection_string=None))
    with pytest.raises(StorageConfigError, match="ZT_S3_ACCESS_KEY_ID"):
        build_providers(settings(storage_providers="aws-s3", s3_access_key_id="AKIAEXAMPLEEXAMPLE12",
                                 s3_secret_access_key=None))
    with pytest.raises(StorageConfigError, match="ZT_S3_BUCKET"):
        build_providers(settings(storage_providers="aws-s3", s3_bucket=""))


def test_build_real_adapters_from_settings():
    ps = build_providers(settings(storage_providers="aws-s3,azure-blob,gcs", s3_endpoint_url=CLOSED,
                                  s3_access_key_id="test", s3_secret_access_key="test",
                                  azure_connection_string=AZURITE, gcs_endpoint_url=CLOSED))
    assert [type(p) for p in ps.values()] == [S3Provider, AzureBlobProvider, GCSProvider]
    assert [p.kind for p in ps.values()] == ["s3", "azure", "gcs"]


def test_build_orchestrator():
    orch = build_orchestrator(settings(), enable_fault_injection=True)
    try:
        assert orch.provider_names == ["memory-a", "memory-b", "memory-c"]
        assert orch.replication_factor == 2 and orch.health is not None
    finally:
        orch.close()


def test_malformed_azure_connection_string_not_echoed():
    secret = "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=TOPSECRETVALUE=="
    with pytest.raises(StorageError) as ei:
        AzureBlobProvider(connection_string=secret + ";garbage", container="c")
    # the SDK rejects the malformed string; our error must not quote it
    assert "TOPSECRETVALUE" not in str(ei.value)


@pytest.mark.parametrize("make", [
    lambda: S3Provider(bucket="b", endpoint_url=CLOSED, access_key_id="test", secret_access_key="sekrit-value",
                       timeout_seconds=1),
    lambda: AzureBlobProvider(connection_string=AZURITE, container="c", timeout_seconds=1),
    lambda: GCSProvider(bucket="b", endpoint_url=CLOSED, timeout_seconds=1),
], ids=["s3", "azure", "gcs"])
def test_connection_refused_translates_to_unavailable_and_health_never_raises(make):
    p = make()
    for call in (lambda: p.get("k"), lambda: p.put("k", b"x"), lambda: p.stat("k"),
                 lambda: list(p.list_keys(""))):
        with pytest.raises(ProviderUnavailable) as ei:
            call()
        msg = str(ei.value)
        assert ei.value.retryable and ei.value.provider == p.name
        assert "sekrit" not in msg and "AccountKey" not in msg and "Eby8" not in msg
    with pytest.raises(ProviderUnavailable):
        p.delete("k")
    st = p.health()
    assert st.healthy is False and st.error and "Eby8" not in st.error


def test_s3_without_credentials_is_auth_error(monkeypatch):
    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    p = S3Provider(bucket="b", endpoint_url=CLOSED, timeout_seconds=1)
    with pytest.raises(ProviderAuthError):
        p.get("k")


def test_sanitize_text_redacts_credentials():
    raw = ("DefaultEndpointsProtocol=https;AccountName=a;AccountKey=abc123==;EndpointSuffix=x "
           "https://bucket.s3.amazonaws.com/k?X-Amz-Signature=deadbeef&X-Amz-Credential=AKIA "
           "AKIAIOSFODNN7EXAMPLE Bearer eyJhbGciOi password=hunter2 https://user:pw@host/x "
           + "Q" * 60 + "\nnext line")
    out = sanitize_text(raw, max_len=1000)
    for bad in ("abc123", "deadbeef", "AKIAIOSFODNN7EXAMPLE", "eyJhbGciOi", "hunter2", "user:pw", "Q" * 60, "\n"):
        assert bad not in out
    assert len(sanitize_text("x" * 500)) <= 200


def test_metadata_validation():
    assert validate_metadata({"fmt": "v1"}) == {"fmt": "v1"}
    for bad in ({"bad key": "v"}, {"k": "line\nbreak"}, {"k": "ünicode"}, {"k": 3}):
        with pytest.raises(StorageError):
            validate_metadata(bad)
