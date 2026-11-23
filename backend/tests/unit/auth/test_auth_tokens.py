import base64
import hashlib
import hmac
import json

import jwt
import pytest
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from app.auth.tokens import TokenService
from app.contracts import KeyPurpose
from app.errors import AuthenticationError


def b64(d: bytes) -> str:
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


def enc(o) -> str:
    return b64(json.dumps(o, separators=(",", ":")).encode())


@pytest.fixture
def ts(kms, settings, clock):
    return TokenService(kms, settings, clock)


def reason(fn):
    with pytest.raises(AuthenticationError) as ei:
        fn()
    return ei.value.reasons[0]


def test_roundtrip_and_claims_are_minimal(ts, kms):
    token, claims = ts.issue_access_token(user_id="u1", session_id="s1")
    assert ts.verify_access_token(token) == claims
    header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
    payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    assert header["alg"] == "EdDSA" and header["kid"].endswith(":1")
    assert set(payload) == {"sub", "sid", "jti", "iat", "exp", "iss", "aud", "typ"}
    assert payload["typ"] == "access" and "role" not in payload
    # interoperable: a standard JWT library verifies it with the KMS public key
    pub = load_pem_public_key(kms.public_key_pem(purpose=KeyPurpose.TOKEN_SIGNING))
    decoded = jwt.decode(token, pub, algorithms=["EdDSA"], audience="zt-api",
                         issuer="zt-multicloud-storage", options={"verify_exp": False, "verify_iat": False})
    assert decoded["sub"] == "u1"


def test_expired_token_strict(ts, clock, settings):
    token, _ = ts.issue_access_token(user_id="u1", session_id="s1")
    clock.advance(settings.access_token_ttl_seconds - 1)
    ts.verify_access_token(token)
    clock.advance(1)          # exactly at exp: no leeway
    assert reason(lambda: ts.verify_access_token(token)) == "token-expired"


def test_future_iat_beyond_leeway(ts, clock):
    token, _ = ts.issue_access_token(user_id="u1", session_id="s1")
    clock.advance(-5)
    ts.verify_access_token(token)
    clock.advance(-1)
    assert reason(lambda: ts.verify_access_token(token)) == "token-not-yet-valid"


def test_tampered_payload_and_signature(ts):
    token, _ = ts.issue_access_token(user_id="u1", session_id="s1")
    h, p, s = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(p + "=="))
    payload["sub"] = "admin"
    assert reason(lambda: ts.verify_access_token(f"{h}.{enc(payload)}.{s}")) == "token-bad-signature"
    sig = bytearray(base64.urlsafe_b64decode(s + "=="))
    sig[0] ^= 1
    assert reason(lambda: ts.verify_access_token(f"{h}.{p}.{b64(bytes(sig))}")) == "token-bad-signature"
    assert reason(lambda: ts.verify_access_token(f"{h}.{p}.")) in ("token-bad-signature", "token-malformed")


def test_alg_none_rejected(ts):
    token, _ = ts.issue_access_token(user_id="u1", session_id="s1")
    _, p, _ = token.split(".")
    for alg in ("none", "None", "NONE"):
        forged = f"{enc({'alg': alg, 'typ': 'JWT'})}.{p}."
        assert reason(lambda: ts.verify_access_token(forged)) in ("token-alg-not-allowed", "token-malformed")
    forged = f"{enc({'alg': 'none', 'typ': 'JWT', 'kid': 'fake-token-signing:1'})}.{p}.{b64(b'x' * 64)}"
    assert reason(lambda: ts.verify_access_token(forged)) == "token-alg-not-allowed"


def test_hs256_with_public_key_rejected(ts, kms):
    token, _ = ts.issue_access_token(user_id="u1", session_id="s1")
    _, p, _ = token.split(".")
    h = enc({"alg": "HS256", "typ": "JWT", "kid": "fake-token-signing:1"})
    pem = kms.public_key_pem(purpose=KeyPurpose.TOKEN_SIGNING)
    sig = hmac.new(pem, f"{h}.{p}".encode(), hashlib.sha256).digest()
    assert reason(lambda: ts.verify_access_token(f"{h}.{p}.{b64(sig)}")) == "token-alg-not-allowed"


def test_wrong_aud_iss_typ_are_rejected_even_if_signed(ts, kms, clock):
    _, claims = ts.issue_access_token(user_id="u1", session_id="s1")
    base = dict(claims.__dict__)

    def signed(**over):
        payload = {**base, **over}
        h = enc({"alg": "EdDSA", "typ": "JWT", "kid": "fake-token-signing:1"})
        p = enc(payload)
        sig = kms.sign(f"{h}.{p}".encode(), purpose=KeyPurpose.TOKEN_SIGNING).signature
        return f"{h}.{p}.{b64(sig)}"

    assert reason(lambda: ts.verify_access_token(signed(aud="other-api"))) == "token-wrong-audience"
    assert reason(lambda: ts.verify_access_token(signed(aud=["zt-api"]))) == "token-wrong-audience"
    assert reason(lambda: ts.verify_access_token(signed(iss="evil"))) == "token-wrong-issuer"
    assert reason(lambda: ts.verify_access_token(signed(typ="refresh"))) == "token-wrong-type"
    assert reason(lambda: ts.verify_access_token(signed(role="admin"))) == "token-bad-claims"
    assert reason(lambda: ts.verify_access_token(signed(exp=base["iat"] + 86400))) == "token-bad-claims"
    no_sid = {k: v for k, v in base.items() if k != "sid"}
    h = enc({"alg": "EdDSA", "typ": "JWT", "kid": "fake-token-signing:1"})
    p = enc(no_sid)
    sig = kms.sign(f"{h}.{p}".encode(), purpose=KeyPurpose.TOKEN_SIGNING).signature
    assert reason(lambda: ts.verify_access_token(f"{h}.{p}.{b64(sig)}")) == "token-bad-claims"


def test_kid_rotation(ts, kms):
    old, _ = ts.issue_access_token(user_id="u1", session_id="s1")
    kms.rotate(KeyPurpose.TOKEN_SIGNING)
    new, _ = ts.issue_access_token(user_id="u1", session_id="s1")
    assert json.loads(base64.urlsafe_b64decode(new.split(".")[0] + "=="))["kid"].endswith(":2")
    ts.verify_access_token(old)
    ts.verify_access_token(new)
    # swapping kid to a version that did not sign the token fails
    h, p, s = old.split(".")
    h2 = enc({"alg": "EdDSA", "kid": "fake-token-signing:2", "typ": "JWT"})
    assert reason(lambda: ts.verify_access_token(f"{h2}.{p}.{s}")) == "token-bad-signature"


@pytest.mark.parametrize("junk", ["", "a.b", "a.b.c.d", "x" * 5000, "é.é.é", None])
def test_malformed(ts, junk):
    with pytest.raises(AuthenticationError):
        ts.verify_access_token(junk)


def test_refresh_tokens_are_256_bit_and_hashed(ts):
    tok, h = ts.new_refresh_token()
    assert len(base64.urlsafe_b64decode(tok + "=")) == 32
    assert h == ts.hash_refresh_token(tok) and tok not in h and len(h) == 64
