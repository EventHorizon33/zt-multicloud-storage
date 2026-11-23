"""The SAME provider contract suite as the unit tests, run against the real
SDK adapters talking to local emulators."""
import pytest

from tests.unit.storage.contract_suite import ProviderContract

pytestmark = pytest.mark.emulator


class TestS3ProviderAgainstMoto(ProviderContract):
    @pytest.fixture
    def provider(self, s3_provider):
        return s3_provider


class TestAzureBlobProviderAgainstAzurite(ProviderContract):
    @pytest.fixture
    def provider(self, azure_provider):
        return azure_provider


class TestGCSProviderAgainstGcpStorageEmulator(ProviderContract):
    @pytest.fixture
    def provider(self, gcs_provider):
        return gcs_provider
