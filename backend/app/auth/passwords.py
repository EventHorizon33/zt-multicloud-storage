"""Password hashing (Argon2id) and password policy.

Security properties:
  * Passwords are stored only as Argon2id encoded hashes (memory-hard, salted
    per password by argon2-cffi with 16 random bytes).
  * ``PasswordHasher.verify_dummy`` performs the same amount of work as a real
    verification, so a login attempt for an unknown username is not
    distinguishable by timing from one with a wrong password.
  * Nothing in this module logs a password or places one in an exception.
"""
from __future__ import annotations

import secrets
import unicodedata

from argon2 import PasswordHasher as _Argon2Hasher
from argon2 import Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.errors import ValidationFailed

#: Upper bound on accepted password length. Argon2 cost is linear in input
#: length only for the initial BLAKE2b pass, but an unbounded input is still a
#: cheap way to waste server CPU/memory, so it is capped.
MAX_PASSWORD_LENGTH = 256

# Parameters: RFC 9106 "second recommended option" (t=3, m=64 MiB, p=4), which
# is above the OWASP Password Storage Cheat Sheet minimum for Argon2id
# (m=19 MiB, t=2, p=1).
DEFAULT_TIME_COST = 3
DEFAULT_MEMORY_COST_KIB = 64 * 1024
DEFAULT_PARALLELISM = 4
HASH_LEN = 32
SALT_LEN = 16

#: Small embedded deny-list of very common passwords (compared case-folded).
#: This is a sanity floor, not a breach-corpus check (see NOTES.md).
COMMON_PASSWORDS: frozenset[str] = frozenset(
    p.casefold()
    for p in (
        "123456", "1234567", "12345678", "123456789", "1234567890", "12345678910",
        "123456789012", "1234567890123", "111111", "000000", "11111111", "111111111111",
        "000000000000", "123123", "123123123", "123123123123", "121212121212",
        "password", "password1", "password12", "password123", "password1234",
        "password12345", "password123456", "passwordpassword", "passw0rd", "p@ssw0rd",
        "p@ssword", "p@ssw0rd123", "p@ssword1234", "passw0rd1234", "password!",
        "password1!", "password123!", "mypassword", "mypassword123", "newpassword123",
        "qwerty", "qwerty123", "qwerty12345", "qwerty123456", "qwertyuiop",
        "qwertyuiop12", "qwertyuiop123", "qwertyuiop[]", "qwertyqwerty", "1q2w3e4r",
        "1q2w3e4r5t", "1q2w3e4r5t6y", "1qaz2wsx", "1qaz2wsx3edc", "qazwsxedc",
        "qazwsxedcrfv", "zaq12wsx", "asdfghjkl", "asdfghjkl123", "asdfghjkl;'",
        "zxcvbnm", "zxcvbnm12345", "abc123", "abc12345", "abc123456789",
        "abcd1234", "abcd12345678", "abcdefgh", "abcdefghijkl", "abcdefg12345",
        "letmein", "letmein123", "letmein12345", "letmeinplease", "welcome",
        "welcome1", "welcome123", "welcome12345", "welcome123456", "welcome@123",
        "admin", "admin123", "admin1234", "admin12345", "admin123456",
        "administrator", "administrator1", "adminadmin", "adminadminadmin", "root",
        "toor", "changeme", "changeme123", "changeme1234", "changemenow",
        "changeme12345", "default", "defaultpassword", "secret", "secret123",
        "supersecret", "supersecret123", "iloveyou", "iloveyou123", "iloveyou1234",
        "iloveyouforever", "monkey", "dragon", "sunshine", "sunshine123",
        "sunshine12345", "princess", "princess1234", "football", "football123",
        "football1234", "baseball", "baseball1234", "superman", "superman1234",
        "batman", "trustno1", "trustno1trustno1", "master", "login",
        "login12345678", "hello123", "hello1234567", "helloworld", "helloworld123",
        "starwars", "starwars1234", "whatever", "whatever1234", "michael",
        "jennifer", "computer", "computer1234", "internet", "internet1234",
        "test", "test123", "test1234", "test12345678", "testtesttest",
        "testpassword", "testpassword1", "temp1234", "temporary123", "summer2024",
        "winter2024", "spring2024", "autumn2024", "summer2024!", "winter2024!",
        "snowflake", "snowflake123", "snowflake1234", "correcthorsebatterystaple",
        "thisisapassword", "thisismypassword", "pleaseletmein", "opensesame",
        "opensesame123", "aaaaaaaaaaaa", "zzzzzzzzzzzz", "google123456", "linkedin1234",
    )
)


def _normalise(password: str) -> str:
    """NFKC-normalise so the same password typed on different platforms
    (composed vs decomposed characters) hashes identically (NIST SP 800-63B)."""
    return unicodedata.normalize("NFKC", password)


def validate_password(password: str, *, username: str, min_length: int) -> None:
    """Enforce the password policy; raise ``ValidationFailed`` with machine
    reason codes. The exception never contains the password itself.

    Rules: length within ``[min_length, MAX_PASSWORD_LENGTH]``, must not
    contain the username (case-insensitive), must not be a very common
    password, must not be a single repeated character.
    """
    reasons: list[str] = []
    if not isinstance(password, str):
        raise ValidationFailed("password does not meet policy", reasons=("password-invalid",))
    pw = _normalise(password)
    if len(pw) < min_length:
        reasons.append("password-too-short")
    if len(pw) > MAX_PASSWORD_LENGTH:
        reasons.append("password-too-long")
    folded = pw.casefold()
    if username and username.casefold() in folded:
        reasons.append("password-contains-username")
    if folded in COMMON_PASSWORDS or (pw and len(set(folded)) == 1):
        reasons.append("password-too-common")
    if reasons:
        raise ValidationFailed("password does not meet policy", reasons=tuple(reasons))


class PasswordHasher:
    """Argon2id hashing with a constant-work path for unknown users.

    Security property: ``verify`` never raises and never reveals why a
    verification failed; ``verify_dummy`` costs the same as ``verify``.
    """

    def __init__(
        self,
        *,
        time_cost: int = DEFAULT_TIME_COST,
        memory_cost_kib: int = DEFAULT_MEMORY_COST_KIB,
        parallelism: int = DEFAULT_PARALLELISM,
    ) -> None:
        self._hasher = _Argon2Hasher(
            time_cost=time_cost,
            memory_cost=memory_cost_kib,
            parallelism=parallelism,
            hash_len=HASH_LEN,
            salt_len=SALT_LEN,
            type=Type.ID,
        )
        # A hash of a random value nobody knows, with the SAME cost parameters,
        # used to burn equivalent time when the username does not exist.
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(32))

    def hash(self, password: str) -> str:
        """Return the Argon2id encoded hash (includes salt and parameters)."""
        return self._hasher.hash(_normalise(password))

    def verify(self, encoded_hash: str, password: str) -> bool:
        """True only if ``password`` matches ``encoded_hash``. Malformed hashes
        and over-long inputs are a mismatch, never an exception."""
        if not isinstance(password, str) or len(password) > MAX_PASSWORD_LENGTH * 4:
            self.verify_dummy("x")
            return False
        try:
            return bool(self._hasher.verify(encoded_hash, _normalise(password)))
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def verify_dummy(self, password: str) -> bool:
        """Do the work of a verification against a throw-away hash and return
        False. Called for unknown usernames to prevent enumeration by timing."""
        if not isinstance(password, str) or len(password) > MAX_PASSWORD_LENGTH * 4:
            password = "x"
        try:
            self._hasher.verify(self._dummy_hash, _normalise(password))
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            pass
        return False

    def needs_rehash(self, encoded_hash: str) -> bool:
        """True if the hash was produced with weaker/different parameters than
        the current ones (the caller re-hashes at the next successful login)."""
        try:
            return bool(self._hasher.check_needs_rehash(encoded_hash))
        except Exception:
            return True
