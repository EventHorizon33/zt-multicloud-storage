from collections import Counter

import pytest

from app.storage import HashPlacement, RotatingPlacement, placement_from_name

NAMES = ["aws-s3", "azure-blob", "gcs"]
STRATEGIES = [RotatingPlacement(), HashPlacement()]


@pytest.mark.parametrize("strategy", STRATEGIES, ids=lambda s: s.name)
def test_return_shape_all_providers_distinct(strategy):
    for i in range(50):
        t = strategy.targets("file-1", f"chunk-{i}", i, NAMES, 2)
        assert sorted(t) == sorted(NAMES)          # every provider exactly once
        assert len(set(t[:2])) == 2                # R distinct preferred targets


@pytest.mark.parametrize("strategy", STRATEGIES, ids=lambda s: s.name)
def test_rejects_bad_replication_factor(strategy):
    with pytest.raises(ValueError):
        strategy.targets("f", "c", 0, NAMES, 4)
    with pytest.raises(ValueError):
        strategy.targets("f", "c", 0, NAMES, 0)
    with pytest.raises(ValueError):
        strategy.targets("f", "c", 0, [], 1)
    with pytest.raises(ValueError):
        strategy.targets("f", "c", 0, ["a", "a"], 1)


@pytest.mark.parametrize("strategy", STRATEGIES, ids=lambda s: s.name)
def test_deterministic(strategy):
    a = [strategy.targets("file-x", f"c{i}", i, NAMES, 2) for i in range(20)]
    b = [strategy.targets("file-x", f"c{i}", i, NAMES, 2) for i in range(20)]
    assert a == b


@pytest.mark.parametrize("strategy", STRATEGIES, ids=lambda s: s.name)
def test_distribution_roughly_even(strategy):
    primaries, replicas = Counter(), Counter()
    for f in range(30):
        for i in range(100):
            t = strategy.targets(f"file-{f}", f"file-{f}-chunk-{i}", i, NAMES, 2)
            primaries[t[0]] += 1
            replicas.update(t[:2])
    total = 3000
    for n in NAMES:
        assert abs(primaries[n] - total / 3) < total * 0.05
        assert abs(replicas[n] - 2 * total / 3) < total * 0.05   # ~2/3 of chunks each with R=2


def test_rotating_ring_order_and_fallbacks():
    p = RotatingPlacement()
    t0 = p.targets("f", "c0", 0, NAMES, 2)
    start = NAMES.index(t0[0])
    for i in range(6):
        t = p.targets("f", f"c{i}", i, NAMES, 2)
        assert t == [NAMES[(start + i + j) % 3] for j in range(3)]  # primary, next replica, fallback


def test_rotating_multi_chunk_file_uses_every_provider():
    p = RotatingPlacement()
    used = set()
    for i in range(3):
        used.update(p.targets("some-file", f"c{i}", i, NAMES, 2)[:2])
    assert used == set(NAMES)
    # and no single provider is a preferred target for every chunk
    for n in NAMES:
        assert not all(n in p.targets("some-file", f"c{i}", i, NAMES, 2)[:2] for i in range(3))


def test_different_files_start_on_different_providers():
    p = RotatingPlacement()
    starts = Counter(p.targets(f"file-{k}", "c0", 0, NAMES, 2)[0] for k in range(300))
    assert set(starts) == set(NAMES)
    assert min(starts.values()) > 60


def test_hash_placement_is_stable_when_provider_added():
    p = HashPlacement()
    moved = 0
    for i in range(600):
        before = p.targets("f", f"c{i}", i, NAMES, 1)[0]
        after = p.targets("f", f"c{i}", i, NAMES + ["extra"], 1)[0]
        if before != after:
            assert after == "extra"   # only moves to the new provider
            moved += 1
    assert 100 < moved < 200          # ~1/4 of chunks move


def test_placement_from_name():
    assert isinstance(placement_from_name("rotating"), RotatingPlacement)
    assert isinstance(placement_from_name("hash"), HashPlacement)
    with pytest.raises(ValueError):
        placement_from_name("random")
