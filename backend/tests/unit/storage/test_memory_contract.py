import pytest

from app.storage import FaultInjectingProvider
from app.storage.memory import MemoryProvider

from .contract_suite import ProviderContract


class TestMemoryProviderContract(ProviderContract):
    @pytest.fixture
    def provider(self):
        return MemoryProvider("memory-a")


class TestFaultWrapperPassThroughContract(ProviderContract):
    """In mode 'none' the fault wrapper must be a transparent provider."""

    @pytest.fixture
    def provider(self):
        return FaultInjectingProvider(MemoryProvider("memory-b"))
