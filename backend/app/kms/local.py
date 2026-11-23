"""File-backed KMS for local/demo deployments.

Key hierarchy::

    root key (32 bytes, supplied out-of-band, never written by this class)
      ├─ HKDF ─> keystore entry-encryption key (AES-256-GCM)
      └─ HKDF ─> keystore MAC key (HMAC-SHA256 over the whole keystore body)
    keystore.json
      └─ per purpose: versioned, independently random keys, each stored
         AES-256-GCM encrypted with AAD = (purpose, key_id, version, alg, created_at)

The keystore file lives apart from the metadata DB and from stored chunks.
See NOTES.md in this package for the on-disk and wrapped-blob formats.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import hmac as _hmac
import json
import logging
import os
import struct
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.contracts import DataKey, KeyInfo, KeyManagementService, KeyPurpose, Signature
from app.errors import KmsError

from ._encoding import canonical_context, lp

try:  # POSIX only; used for cross-process serialisation of keystore writes
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

ROOT_KEY_BYTES = 32
DATA_KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
MAX_SECRET_BYTES = 64 * 1024

ALG_AES = "AES-256-GCM"
ALG_ED25519 = "Ed25519"
ALG_HMAC = "HMAC-SHA256"

_ALGORITHMS: dict[KeyPurpose, str] = {
    KeyPurpose.FILE_DEK_WRAP: ALG_AES,
    KeyPurpose.SECRET_ENCRYPTION: ALG_AES,
    KeyPurpose.TOKEN_SIGNING: ALG_ED25519,
    KeyPurpose.AUDIT_SIGNING: ALG_ED25519,
    KeyPurpose.AUDIT_PSEUDONYM: ALG_HMAC,
    KeyPurpose.LOOKUP_HMAC: ALG_HMAC,
}

# ---- wrapped-blob format (see NOTES.md) ------------------------------------
BLOB_MAGIC = b"ZTK1"           # "ZTK" + format version 1
KIND_DATA_KEY = 0x01
KIND_SECRET = 0x02
_KIND_PURPOSE = {
    KIND_DATA_KEY: KeyPurpose.FILE_DEK_WRAP,
    KIND_SECRET: KeyPurpose.SECRET_ENCRYPTION,
}
_BLOB_AAD_DOMAIN = b"zt-kms-blob-aad-v1"

# ---- keystore file format ---------------------------------------------------
KEYSTORE_FORMAT = "zt-kms-keystore"
KEYSTORE_VERSION = 1
_ENTRY_AAD_DOMAIN = b"zt-kms-keystore-entry-v1"
_INFO_ENTRY_KEY = b"zt-kms/keystore/entry-encryption/v1"
_INFO_MAC_KEY = b"zt-kms/keystore/mac/v1"

STATE_ACTIVE = "active"
STATE_DECRYPT_ONLY = "decrypt-only"


@dataclass(frozen=True)
class ParsedBlob:
    """Header of a wrapped blob. Contains no key material."""
    kind: int
    key_id: str
    version: int
    header: bytes      # magic .. version (authenticated as AAD)
    nonce: bytes
    ciphertext: bytes  # AES-GCM ciphertext || tag


def parse_blob(blob: bytes) -> ParsedBlob:
    """Parse the self-describing header of a LocalKMS blob.

    Raises :class:`KmsError` for anything that is not a well-formed blob. The
    header is *not* trusted until the AEAD tag has been verified (the header
    is part of the associated data).
    """
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise KmsError("wrapped blob must be bytes")
    blob = bytes(blob)
    if len(blob) < 6 or blob[:4] != BLOB_MAGIC:
        raise KmsError("unrecognised wrapped-blob format")
    kind = blob[4]
    if kind not in _KIND_PURPOSE:
        raise KmsError("unrecognised wrapped-blob kind")
    id_len = blob[5]
    header_len = 6 + id_len + 4
    if id_len == 0 or len(blob) < header_len + NONCE_BYTES + TAG_BYTES:
        raise KmsError("wrapped blob is truncated")
    try:
        key_id = blob[6:6 + id_len].decode("ascii")
    except UnicodeDecodeError:
        raise KmsError("malformed wrapped-blob header") from None
    (version,) = struct.unpack(">I", blob[6 + id_len:header_len])
    if version < 1:
        raise KmsError("malformed wrapped-blob header")
    return ParsedBlob(
        kind=kind,
        key_id=key_id,
        version=version,
        header=blob[:header_len],
        nonce=blob[header_len:header_len + NONCE_BYTES],
        ciphertext=blob[header_len + NONCE_BYTES:],
    )


def _blob_header(kind: int, key_id: str, version: int) -> bytes:
    kid = key_id.encode("ascii")
    if not 0 < len(kid) < 256:
        raise KmsError("key id not encodable")
    return BLOB_MAGIC + bytes([kind, len(kid)]) + kid + struct.pack(">I", version)


def _blob_aad(header: bytes, context: Mapping[str, str]) -> bytes:
    return _BLOB_AAD_DOMAIN + lp(header) + canonical_context(context)


def _key_id(purpose: KeyPurpose) -> str:
    return f"local/{purpose.value}"


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: Any) -> bytes:
    if not isinstance(text, str):
        raise KmsError("keystore is malformed")
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise KmsError("keystore is malformed") from None


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


class _KeyVersion:
    """One version of one purpose's key. ``material`` is secret."""
    __slots__ = ("version", "algorithm", "created_at", "nonce", "ciphertext", "material")

    def __init__(self, version: int, algorithm: str, created_at: str,
                 nonce: bytes, ciphertext: bytes, material: bytes):
        self.version = version
        self.algorithm = algorithm
        self.created_at = created_at
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.material = material

    def __repr__(self) -> str:  # never show material
        return f"<_KeyVersion v{self.version} {self.algorithm}>"


class LocalKMS(KeyManagementService):
    """Versioned keystore in a JSON file, encrypted under an out-of-band root key.

    Security properties:
      * key material is only ever written to disk AES-256-GCM encrypted, with
        associated data that pins each entry to its (purpose, key_id, version,
        algorithm, creation time); the whole file body is additionally
        HMAC-protected, so entries cannot be swapped, edited, added or removed
        without the root key;
      * every purpose has its own independent random key;
      * only the newest version of a purpose is used to wrap/encrypt/sign/MAC;
        older versions are decrypt/verify-only;
      * wrapped blobs are bound to the caller's context: unwrap with any other
        context, any modified byte, or an unknown key version raises KmsError.

    Thread-safe within a process (re-entrant lock). Keystore writes are also
    serialised across processes on POSIX with an advisory file lock, and a
    process re-reads the file when it sees that it changed on disk.
    """

    def __init__(self, keystore_path: str | os.PathLike[str], root_key: bytes, *,
                 clock: Callable[[], datetime] | None = None):
        if not isinstance(root_key, (bytes, bytearray)) or len(root_key) != ROOT_KEY_BYTES:
            raise KmsError("root key must be exactly 32 bytes")
        root = bytes(root_key)
        self._path = Path(keystore_path)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self._entry_aead = AESGCM(self._derive(root, _INFO_ENTRY_KEY))
        self._mac_key = self._derive(root, _INFO_MAC_KEY)
        self._keys: dict[KeyPurpose, list[_KeyVersion]] = {}
        self._disk_sig: tuple[int, int, int] | None = None
        with self._lock:
            self._refresh()

    def __repr__(self) -> str:
        return f"LocalKMS(keystore_path={str(self._path)!r})"

    # ------------------------------------------------------------------ #
    # contract: data keys
    # ------------------------------------------------------------------ #
    def generate_data_key(self, *, context: Mapping[str, str]) -> DataKey:
        """Fresh random 256-bit data key, returned in plaintext and wrapped
        under the active FILE_DEK_WRAP version bound to ``context``."""
        plaintext = os.urandom(DATA_KEY_BYTES)
        wrapped, key_id, version = self._seal(KIND_DATA_KEY, plaintext, context)
        return DataKey(plaintext=plaintext, wrapped=wrapped, key_id=key_id, key_version=version)

    def unwrap_data_key(self, wrapped: bytes, *, context: Mapping[str, str]) -> bytes:
        """Return the data key, or raise KmsError. Never returns unauthenticated bytes."""
        plaintext = self._open(KIND_DATA_KEY, wrapped, context)
        if len(plaintext) != DATA_KEY_BYTES:
            raise KmsError("unwrap failed")
        return plaintext

    def rewrap_data_key(self, wrapped: bytes, *, context: Mapping[str, str]) -> DataKey:
        """Unwrap (any known version) and wrap again under the active version.
        The returned ``DataKey.plaintext`` is always ``b""``."""
        plaintext = self.unwrap_data_key(wrapped, context=context)
        new_wrapped, key_id, version = self._seal(KIND_DATA_KEY, plaintext, context)
        return DataKey(plaintext=b"", wrapped=new_wrapped, key_id=key_id, key_version=version)

    def wrapped_key_version(self, wrapped: bytes) -> tuple[str, int]:
        """(key_id, version) from the blob header only. Nothing is decrypted,
        so the result is unauthenticated: use it for planning rotation, not
        for security decisions."""
        parsed = parse_blob(wrapped)
        if parsed.kind != KIND_DATA_KEY:
            raise KmsError("not a wrapped data key")
        return parsed.key_id, parsed.version

    # ------------------------------------------------------------------ #
    # contract: small secrets
    # ------------------------------------------------------------------ #
    def encrypt(self, plaintext: bytes, *, context: Mapping[str, str]) -> bytes:
        """Encrypt a small secret under the active SECRET_ENCRYPTION version,
        bound to ``context``."""
        if not isinstance(plaintext, (bytes, bytearray)):
            raise KmsError("plaintext must be bytes")
        if len(plaintext) > MAX_SECRET_BYTES:
            raise KmsError("secret too large for KMS encrypt")
        blob, _, _ = self._seal(KIND_SECRET, bytes(plaintext), context)
        return blob

    def decrypt(self, ciphertext: bytes, *, context: Mapping[str, str]) -> bytes:
        return self._open(KIND_SECRET, ciphertext, context)

    # ------------------------------------------------------------------ #
    # contract: signatures and MACs
    # ------------------------------------------------------------------ #
    def sign(self, message: bytes, *, purpose: KeyPurpose) -> Signature:
        """Ed25519 signature with the active version of a signing purpose."""
        purpose = self._require(purpose, ALG_ED25519)
        with self._lock:
            kv = self._active(purpose, create=True)
            material = kv.material
            version = kv.version
        sig = Ed25519PrivateKey.from_private_bytes(material).sign(bytes(message))
        return Signature(key_id=_key_id(purpose), version=version, signature=sig)

    def verify(self, message: bytes, signature: bytes, *, purpose: KeyPurpose,
               key_id: str, version: int) -> bool:
        """True only for a valid Ed25519 signature by the named key version.
        Returns False (never raises) for a bad signature, a wrong key id or an
        unknown version."""
        purpose = self._require(purpose, ALG_ED25519)
        if not isinstance(key_id, str) or not _hmac.compare_digest(
                key_id.encode("utf-8", "replace"), _key_id(purpose).encode("ascii")):
            return False
        if isinstance(version, bool) or not isinstance(version, int):
            return False
        with self._lock:
            kv = self._version(purpose, version)
            if kv is None:
                return False
            material = kv.material
        try:
            public = Ed25519PrivateKey.from_private_bytes(material).public_key()
            public.verify(bytes(signature), bytes(message))
        except (InvalidSignature, TypeError, ValueError):
            return False
        return True

    def public_key_pem(self, *, purpose: KeyPurpose, version: int | None = None) -> bytes:
        """SubjectPublicKeyInfo PEM of a signing key version (active if None)."""
        purpose = self._require(purpose, ALG_ED25519)
        with self._lock:
            if version is None:
                kv: _KeyVersion | None = self._active(purpose, create=True)
            else:
                kv = self._version(purpose, version)
            if kv is None:
                raise KmsError("unknown key version")
            material = kv.material
        public: Ed25519PublicKey = Ed25519PrivateKey.from_private_bytes(material).public_key()
        return public.public_bytes(serialization.Encoding.PEM,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)

    def mac(self, message: bytes, *, purpose: KeyPurpose) -> bytes:
        """HMAC-SHA256 under the active version of an HMAC purpose."""
        purpose = self._require(purpose, ALG_HMAC)
        with self._lock:
            material = self._active(purpose, create=True).material
        h = hmac.HMAC(material, hashes.SHA256())
        h.update(bytes(message))
        return h.finalize()

    def mac_all_versions(self, message: bytes, *, purpose: KeyPurpose) -> list[bytes]:
        """HMAC-SHA256 under every version of an HMAC purpose, newest first."""
        purpose = self._require(purpose, ALG_HMAC)
        with self._lock:
            self._active(purpose, create=True)
            materials = [kv.material for kv in reversed(self._keys.get(purpose, []))]
        out = []
        for material in materials:
            h = hmac.HMAC(material, hashes.SHA256())
            h.update(bytes(message))
            out.append(h.finalize())
        return out

    # ------------------------------------------------------------------ #
    # contract: lifecycle
    # ------------------------------------------------------------------ #
    def rotate(self, purpose: KeyPurpose) -> KeyInfo:
        """Add a new active version. Earlier versions remain for
        unwrap/decrypt/verify only."""
        purpose = self._purpose(purpose)
        with self._mutating():
            kv = self._new_version(purpose)
            self._persist()
        logger.info("kms key rotated purpose=%s version=%d", purpose.value, kv.version)
        return self._info(purpose, kv, STATE_ACTIVE)

    def list_keys(self) -> list[KeyInfo]:
        """Metadata for every key version. Never contains key material."""
        with self._lock:
            self._refresh()
            out: list[KeyInfo] = []
            for purpose in KeyPurpose:
                versions = self._keys.get(purpose, [])
                for kv in versions:
                    state = STATE_ACTIVE if kv is versions[-1] else STATE_DECRYPT_ONLY
                    out.append(self._info(purpose, kv, state))
            return out

    def ensure_keys(self) -> list[KeyInfo]:
        """Create version 1 of every purpose that has no key yet."""
        with self._mutating():
            created = False
            for purpose in KeyPurpose:
                if not self._keys.get(purpose):
                    self._new_version(purpose)
                    created = True
            if created:
                self._persist()
        return self.list_keys()

    # ------------------------------------------------------------------ #
    # internals: AEAD blobs
    # ------------------------------------------------------------------ #
    def _seal(self, kind: int, plaintext: bytes, context: Mapping[str, str]) -> tuple[bytes, str, int]:
        purpose = _KIND_PURPOSE[kind]
        key_id = _key_id(purpose)
        aad_ctx = canonical_context(context)  # validates before any key use
        with self._lock:
            kv = self._active(purpose, create=True)
            material, version = kv.material, kv.version
        header = _blob_header(kind, key_id, version)
        nonce = os.urandom(NONCE_BYTES)
        ct = AESGCM(material).encrypt(nonce, plaintext, _BLOB_AAD_DOMAIN + lp(header) + aad_ctx)
        return header + nonce + ct, key_id, version

    def _open(self, kind: int, blob: bytes, context: Mapping[str, str]) -> bytes:
        parsed = parse_blob(blob)
        purpose = _KIND_PURPOSE[kind]
        if parsed.kind != kind or parsed.key_id != _key_id(purpose):
            raise KmsError("blob was not produced for this purpose")
        aad = _blob_aad(parsed.header, context)
        with self._lock:
            kv = self._version(purpose, parsed.version)
            if kv is None:
                raise KmsError("unknown key version")
            material = kv.material
        try:
            return AESGCM(material).decrypt(parsed.nonce, parsed.ciphertext, aad)
        except InvalidTag:
            raise KmsError("authentication failed: wrong context or modified blob") from None

    # ------------------------------------------------------------------ #
    # internals: key table (call with self._lock held)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _derive(root: bytes, info: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(root)

    @staticmethod
    def _purpose(purpose: KeyPurpose | str) -> KeyPurpose:
        try:
            return KeyPurpose(purpose)
        except ValueError:
            raise KmsError("unknown key purpose") from None

    def _require(self, purpose: KeyPurpose | str, algorithm: str) -> KeyPurpose:
        p = self._purpose(purpose)
        if _ALGORITHMS[p] != algorithm:
            raise KmsError(f"purpose {p.value} cannot be used for {algorithm}")
        return p

    def _active(self, purpose: KeyPurpose, *, create: bool) -> _KeyVersion:
        self._refresh()
        versions = self._keys.get(purpose)
        if versions:
            return versions[-1]
        if not create:
            raise KmsError("no key for purpose")
        with self._mutating():
            versions = self._keys.get(purpose)
            if not versions:
                self._new_version(purpose)
                self._persist()
                logger.info("kms key created purpose=%s version=1", purpose.value)
            return self._keys[purpose][-1]

    def _version(self, purpose: KeyPurpose, version: int) -> _KeyVersion | None:
        self._refresh()
        for kv in self._keys.get(purpose, []):
            if kv.version == version:
                return kv
        return None

    def _new_version(self, purpose: KeyPurpose) -> _KeyVersion:
        algorithm = _ALGORITHMS[purpose]
        if algorithm == ALG_ED25519:
            material = Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption())
        else:
            material = os.urandom(32)
        versions = self._keys.setdefault(purpose, [])
        version = versions[-1].version + 1 if versions else 1
        created_at = self._clock().astimezone(timezone.utc).isoformat()
        nonce = os.urandom(NONCE_BYTES)
        ct = self._entry_aead.encrypt(
            nonce, material, self._entry_aad(purpose, version, algorithm, created_at))
        kv = _KeyVersion(version, algorithm, created_at, nonce, ct, material)
        versions.append(kv)
        return kv

    @staticmethod
    def _entry_aad(purpose: KeyPurpose, version: int, algorithm: str, created_at: str) -> bytes:
        return (_ENTRY_AAD_DOMAIN
                + lp(purpose.value.encode("ascii"))
                + lp(_key_id(purpose).encode("ascii"))
                + struct.pack(">I", version)
                + lp(algorithm.encode("ascii"))
                + lp(created_at.encode("utf-8")))

    @staticmethod
    def _info(purpose: KeyPurpose, kv: _KeyVersion, state: str) -> KeyInfo:
        return KeyInfo(purpose=purpose.value, key_id=_key_id(purpose), version=kv.version,
                       algorithm=kv.algorithm, created_at=datetime.fromisoformat(kv.created_at),
                       state=state)

    # ------------------------------------------------------------------ #
    # internals: persistence
    # ------------------------------------------------------------------ #
    @contextlib.contextmanager
    def _mutating(self) -> Iterator[None]:
        """Hold the process lock and the cross-process file lock, with the
        in-memory table refreshed from disk, for a read-modify-write."""
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = None
            if fcntl is not None:
                fd = os.open(str(self._path) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
            try:
                if fd is not None:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                self._refresh()
                yield
            finally:
                if fd is not None:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    finally:
                        os.close(fd)

    def _stat_sig(self) -> tuple[int, int, int] | None:
        try:
            st = os.stat(self._path)
        except FileNotFoundError:
            return None
        return (st.st_mtime_ns, st.st_size, st.st_ino)

    def _refresh(self) -> None:
        """Reload the keystore if the file changed since we last read/wrote it."""
        sig = self._stat_sig()
        if sig == self._disk_sig:
            return
        if sig is None:
            # We had a keystore and it vanished: refuse to continue from memory.
            raise KmsError("keystore file is missing")
        try:
            raw = self._path.read_bytes()
        except OSError:
            raise KmsError("keystore file could not be read") from None
        self._keys = self._parse(raw)
        self._disk_sig = sig

    def _parse(self, raw: bytes) -> dict[KeyPurpose, list[_KeyVersion]]:
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise KmsError("keystore is malformed") from None
        if (not isinstance(doc, dict) or doc.get("format") != KEYSTORE_FORMAT
                or doc.get("v") != KEYSTORE_VERSION or not isinstance(doc.get("keys"), dict)
                or not isinstance(doc.get("mac"), str)):
            raise KmsError("keystore is malformed or has an unsupported version")
        body = {"format": doc["format"], "v": doc["v"], "keys": doc["keys"]}
        expected = _hmac.new(self._mac_key, _canonical(body), hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(expected.encode("ascii"), doc["mac"].encode("utf-8", "replace")):
            raise KmsError("keystore authentication failed: wrong root key or modified keystore")

        keys: dict[KeyPurpose, list[_KeyVersion]] = {}
        for purpose_name, entry in doc["keys"].items():
            purpose = self._purpose(purpose_name)
            if (not isinstance(entry, dict) or entry.get("key_id") != _key_id(purpose)
                    or not isinstance(entry.get("versions"), list) or not entry["versions"]):
                raise KmsError("keystore is malformed")
            versions: list[_KeyVersion] = []
            for n, item in enumerate(entry["versions"], start=1):
                if not isinstance(item, dict):
                    raise KmsError("keystore is malformed")
                version, algorithm, created_at = item.get("v"), item.get("alg"), item.get("created_at")
                if (version != n or isinstance(version, bool) or algorithm != _ALGORITHMS[purpose]
                        or not isinstance(created_at, str)):
                    raise KmsError("keystore is malformed")
                nonce, ct = _b64d(item.get("nonce")), _b64d(item.get("ct"))
                if len(nonce) != NONCE_BYTES:
                    raise KmsError("keystore is malformed")
                try:
                    material = self._entry_aead.decrypt(
                        nonce, ct, self._entry_aad(purpose, version, algorithm, created_at))
                    datetime.fromisoformat(created_at)
                except InvalidTag:
                    raise KmsError("keystore entry authentication failed") from None
                except ValueError:
                    raise KmsError("keystore is malformed") from None
                if len(material) != 32:
                    raise KmsError("keystore is malformed")
                versions.append(_KeyVersion(version, algorithm, created_at, nonce, ct, material))
            keys[purpose] = versions
        return keys

    def _serialise(self) -> bytes:
        keys_doc: dict[str, Any] = {}
        for purpose, versions in self._keys.items():
            if not versions:
                continue
            keys_doc[purpose.value] = {
                "key_id": _key_id(purpose),
                "versions": [
                    {"v": kv.version, "alg": kv.algorithm, "created_at": kv.created_at,
                     "nonce": _b64e(kv.nonce), "ct": _b64e(kv.ciphertext)}
                    for kv in versions
                ],
            }
        body = {"format": KEYSTORE_FORMAT, "v": KEYSTORE_VERSION, "keys": keys_doc}
        mac = _hmac.new(self._mac_key, _canonical(body), hashlib.sha256).hexdigest()
        return json.dumps({**body, "mac": mac}, sort_keys=True, indent=1).encode("ascii")

    def _persist(self) -> None:
        """Atomic replace: temp file (0600) + fsync + os.replace + dir fsync."""
        data = self._serialise()
        directory = self._path.parent
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = directory / f".{self._path.name}.{os.getpid()}.{os.urandom(6).hex()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self._path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
        except OSError:
            # In-memory state may now be ahead of disk: force a reload.
            self._disk_sig = (-1, -1, -1)
            raise KmsError("keystore could not be written") from None
        with contextlib.suppress(OSError):
            dfd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        self._disk_sig = self._stat_sig()


# --------------------------------------------------------------------------- #
# root key loading
# --------------------------------------------------------------------------- #
DEV_ROOT_KEY_NAME = "dev-root.key"
_DEV_ENVS = ("test", "development")


def _decode_root_key(text: str, source: str) -> bytes:
    try:
        key = base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise KmsError(f"KMS root key from {source} is not valid base64") from None
    if len(key) != ROOT_KEY_BYTES:
        raise KmsError(f"KMS root key from {source} must decode to exactly 32 bytes")
    return key


def load_root_key(settings: Any) -> bytes:
    """Resolve the 32-byte keystore root key.

    Order: ``settings.kms_root_key`` (base64), then ``settings.kms_root_key_file``
    (file containing base64). With neither set: in env ``test``/``development``
    a key is generated once and kept at ``<data_dir>/kms/dev-root.key`` (0600)
    with a WARNING; in any other env (``production``) this raises
    :class:`KmsError`. The key value is never logged or put in an exception.
    """
    inline = getattr(settings, "kms_root_key", None)
    if inline:
        return _decode_root_key(inline, "ZT_KMS_ROOT_KEY")
    key_file = getattr(settings, "kms_root_key_file", None)
    if key_file:
        try:
            text = Path(key_file).read_text(encoding="ascii")
        except (OSError, UnicodeDecodeError):
            raise KmsError("KMS root key file could not be read") from None
        return _decode_root_key(text, "the root key file")

    env = getattr(settings, "env", "production")
    if env not in _DEV_ENVS:
        raise KmsError(
            "no KMS root key configured: set ZT_KMS_ROOT_KEY or ZT_KMS_ROOT_KEY_FILE "
            f"(auto-generated keys are only allowed in {'/'.join(_DEV_ENVS)}, env is {env!r})")

    directory = Path(settings.data_dir) / "kms"
    path = directory / DEV_ROOT_KEY_NAME
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            key = _decode_root_key(path.read_text(encoding="ascii"), "the development key file")
            logger.warning("using DEVELOPMENT-ONLY KMS root key file %s; never use this in production", path)
            return key
        key = os.urandom(ROOT_KEY_BYTES)
        with os.fdopen(fd, "wb") as fh:
            fh.write(base64.b64encode(key) + b"\n")
            fh.flush()
            os.fsync(fh.fileno())
    except (OSError, UnicodeDecodeError):
        raise KmsError("development KMS root key file could not be created or read") from None
    logger.warning(
        "generated a DEVELOPMENT-ONLY KMS root key at %s (stored next to the keystore, "
        "so it protects nothing against someone who can read that directory); "
        "set ZT_KMS_ROOT_KEY or ZT_KMS_ROOT_KEY_FILE for any real deployment", path)
    return key
