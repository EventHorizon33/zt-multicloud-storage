import time

import pytest
from argon2 import PasswordHasher as RawArgon2

from app.auth.passwords import PasswordHasher, validate_password
from app.errors import ValidationFailed


def test_default_parameters_are_argon2id_owasp_or_stronger():
    h = PasswordHasher()
    encoded = h.hash("correct horse battery")
    assert encoded.startswith("$argon2id$v=19$")
    params = dict(p.split("=") for p in encoded.split("$")[3].split(","))
    assert int(params["m"]) >= 19 * 1024 and int(params["t"]) >= 2 and int(params["p"]) >= 1
    assert h.verify(encoded, "correct horse battery")
    assert not h.verify(encoded, "correct horse batterY")
    assert not h.needs_rehash(encoded)


def test_hash_is_salted():
    h = PasswordHasher(time_cost=1, memory_cost_kib=8, parallelism=1)
    assert h.hash("same-password-here") != h.hash("same-password-here")


def test_verify_never_raises_on_garbage():
    h = PasswordHasher(time_cost=1, memory_cost_kib=8, parallelism=1)
    assert h.verify("not-a-hash", "x") is False
    assert h.verify(h.hash("abc"), None) is False          # type: ignore[arg-type]
    assert h.verify(h.hash("abc"), "a" * 10_000) is False


def test_needs_rehash_for_weaker_parameters():
    weak = RawArgon2(time_cost=1, memory_cost=8, parallelism=1).hash("pw")
    assert PasswordHasher().needs_rehash(weak)


def test_dummy_verify_costs_about_the_same_as_real_verify():
    h = PasswordHasher(time_cost=2, memory_cost_kib=16 * 1024, parallelism=1)
    encoded = h.hash("some-password-123")
    def timed(fn):
        best = 1e9
        for _ in range(3):
            t = time.perf_counter(); fn(); best = min(best, time.perf_counter() - t)
        return best
    real = timed(lambda: h.verify(encoded, "wrong-password-123"))
    dummy = timed(lambda: h.verify_dummy("wrong-password-123"))
    assert h.verify_dummy("anything") is False
    assert 0.5 < dummy / real < 2.0


@pytest.mark.parametrize("pw,reason", [
    ("short1!", "password-too-short"),
    ("alice-is-great-123", "password-contains-username"),
    ("xxALICExx-secure-99", "password-contains-username"),
    ("password1234", "password-too-common"),
    ("Qwerty123456", "password-too-common"),
    ("aaaaaaaaaaaaaaaa", "password-too-common"),
    ("x" * 300, "password-too-long"),
])
def test_password_policy_rejections(pw, reason):
    with pytest.raises(ValidationFailed) as ei:
        validate_password(pw, username="alice", min_length=12)
    assert reason in ei.value.reasons
    assert pw not in str(ei.value)


def test_password_policy_accepts_good_password():
    validate_password("plum-orbit-violin-42", username="alice", min_length=12)
