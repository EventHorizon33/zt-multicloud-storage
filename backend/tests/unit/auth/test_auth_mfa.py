from datetime import datetime, timezone

import pyotp

from app.auth.mfa import TotpService, check_code, code_at, generate_seed, time_step
from tests.unit._fakes_auth import FakeKms

NOW = datetime(2026, 11, 12, 12, 0, 10, tzinfo=timezone.utc)


def test_code_matches_pyotp_rfc6238():
    seed = generate_seed()
    assert code_at(seed, NOW) == pyotp.TOTP(seed).at(NOW)


def test_window_is_plus_minus_one_step():
    seed = generate_seed()
    for off in (-1, 0, 1):
        assert check_code(seed, code_at(seed, NOW, step_offset=off), now=NOW, last_counter=None).ok
    for off in (-2, 2):
        r = check_code(seed, code_at(seed, NOW, step_offset=off), now=NOW, last_counter=None)
        assert not r.ok and r.reason == "mfa-invalid"


def test_replay_of_accepted_counter_rejected():
    seed = generate_seed()
    code = code_at(seed, NOW)
    first = check_code(seed, code, now=NOW, last_counter=None)
    assert first.ok and first.counter == time_step(NOW)
    again = check_code(seed, code, now=NOW, last_counter=first.counter)
    assert not again.ok and again.reason == "mfa-replay"
    # an older (previous-step) code is also refused once a newer one was used
    older = check_code(seed, code_at(seed, NOW, step_offset=-1), now=NOW, last_counter=first.counter)
    assert not older.ok


def test_malformed_codes():
    seed = generate_seed()
    for bad in (None, "", "12345", "1234567", "abcdef", "١٢٣٤٥٦", 123456):
        assert not check_code(seed, bad, now=NOW, last_counter=None).ok


def test_seed_is_kms_encrypted_and_context_bound():
    kms = FakeKms()
    svc = TotpService(kms, issuer="zt")
    enrol, blob = svc.new_enrollment(user_id="u1", account_name="alice")
    assert enrol.secret.encode() not in blob
    assert enrol.otpauth_uri.startswith("otpauth://totp/")
    code = code_at(enrol.secret, NOW)
    assert svc.verify(user_id="u1", encrypted_seed=blob, code=code, now=NOW, last_counter=None).ok
    # the same blob copied to another user's row does not decrypt
    assert not svc.verify(user_id="u2", encrypted_seed=blob, code=code, now=NOW, last_counter=None).ok
