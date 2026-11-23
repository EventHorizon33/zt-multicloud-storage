"""Placement strategies: which providers hold which chunk.

Return shape of ``targets(...)`` (both strategies): a list containing EVERY
provider name exactly once. The first ``replication_factor`` entries are the
preferred replica targets in priority order (index 0 = primary); the remaining
entries are ordered fallback candidates the orchestrator uses, in that order,
when a preferred target fails. Deterministic: same inputs, same output.

Security property: dispersal. With R < n no single provider is the preferred
target for every chunk of a file, so one compromised provider credential
yields only a subset of a file's ciphertext chunks (ADR-0004).
"""
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from typing import Sequence


def _check(provider_names: Sequence[str], replication_factor: int) -> list[str]:
    names = list(provider_names)
    if not names:
        raise ValueError("no storage providers configured")
    if len(set(names)) != len(names):
        raise ValueError("provider names must be unique")
    if replication_factor < 1:
        raise ValueError("replication_factor must be >= 1")
    if replication_factor > len(names):
        raise ValueError(f"replication_factor {replication_factor} exceeds the number of providers "
                         f"({len(names)})")
    return names


class PlacementStrategy(ABC):
    name: str

    @abstractmethod
    def targets(self, file_id: str, chunk_id: str, chunk_index: int,
                provider_names: Sequence[str], replication_factor: int) -> list[str]:
        """See module docstring for the exact return shape."""


class RotatingPlacement(PlacementStrategy):
    """chunk i: primary = names[(offset + i) % n], replicas = the next R-1
    providers in ring order, fallbacks = the rest of the ring. ``offset`` is
    derived from SHA-256(file_id) so different files start on different
    providers. Gives a perfectly even spread within a file."""

    name = "rotating"

    def targets(self, file_id: str, chunk_id: str, chunk_index: int,
                provider_names: Sequence[str], replication_factor: int) -> list[str]:
        names = _check(provider_names, replication_factor)
        if chunk_index < 0:
            raise ValueError("chunk_index must be >= 0")
        n = len(names)
        offset = int.from_bytes(hashlib.sha256(file_id.encode()).digest()[:8], "big") % n
        start = (offset + chunk_index) % n
        return [names[(start + j) % n] for j in range(n)]


class HashPlacement(PlacementStrategy):
    """Rendezvous (highest-random-weight) hashing on the chunk id: providers
    are ordered by SHA-256(chunk_id | provider) descending. Adding or removing
    a provider moves only the chunks whose top-R set changes."""

    name = "hash"

    def targets(self, file_id: str, chunk_id: str, chunk_index: int,
                provider_names: Sequence[str], replication_factor: int) -> list[str]:
        names = _check(provider_names, replication_factor)

        def weight(provider: str) -> bytes:
            return hashlib.sha256(f"{chunk_id}\x00{provider}".encode()).digest()

        return sorted(names, key=lambda p: (weight(p), p), reverse=True)


def placement_from_name(name: str) -> PlacementStrategy:
    if name == "rotating":
        return RotatingPlacement()
    if name == "hash":
        return HashPlacement()
    raise ValueError(f"unknown placement strategy {name!r} (expected 'rotating' or 'hash')")
