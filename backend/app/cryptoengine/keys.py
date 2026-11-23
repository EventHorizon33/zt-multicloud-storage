"""Per-file key derivation (ADR-0001).

One 256-bit data key (DEK) per file; three independent sub-keys derived with
HKDF-SHA256 under distinct ``info`` labels, each also bound to the file id.
"""
from __future__ import annotations

import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DEK_BYTES = 32
_KDF_DOMAIN = b"zt-mcs/file-keys/v1"
LABEL_CHUNK_ENCRYPTION = b"chunk-encryption"
LABEL_MANIFEST_MAC = b"manifest-mac"
LABEL_METADATA_ENCRYPTION = b"metadata-encryption"
MAX_FILE_ID_BYTES = 255


def encode_file_id(file_id: str) -> bytes:
    """UTF-8 bytes of a file id, validated (non-empty str, <= 255 bytes)."""
    if not isinstance(file_id, str) or not file_id:
        raise ValueError("file_id must be a non-empty string")
    try:
        raw = file_id.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("file_id must be valid unicode") from None
    if len(raw) > MAX_FILE_ID_BYTES:
        raise ValueError("file_id is too long")
    return raw


def _lp(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _derive(dek: bytes, label: bytes, file_id: bytes) -> bytes:
    info = _lp(_KDF_DOMAIN) + _lp(label) + _lp(file_id)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(dek)


class FileKeys:
    """The three working keys of one file, held in memory only.

    Security properties: ``k_enc`` (chunk AES-256-GCM), ``k_mac`` (manifest
    HMAC-SHA256) and ``k_meta`` (metadata AES-256-GCM) are computationally
    independent; knowing or misusing one does not help with another, and the
    same DEK used with a different ``file_id`` yields unrelated keys. The DEK
    itself is not retained.

    ``repr``/``str`` never show key bytes and the object refuses to be
    pickled. :meth:`destroy` drops the references so the keys become
    unreachable; CPython gives no way to guarantee that the underlying memory
    is overwritten, so this is best effort, not secure erasure.
    """

    __slots__ = ("_file_id", "_k_enc", "_k_mac", "_k_meta", "_enc_aead", "_meta_aead")

    def __init__(self, file_id: str, k_enc: bytes, k_mac: bytes, k_meta: bytes):
        encode_file_id(file_id)
        for k in (k_enc, k_mac, k_meta):
            if not isinstance(k, bytes) or len(k) != 32:
                raise ValueError("file keys must be 32 bytes each")
        self._file_id = file_id
        self._k_enc: bytes | None = k_enc
        self._k_mac: bytes | None = k_mac
        self._k_meta: bytes | None = k_meta
        self._enc_aead: AESGCM | None = AESGCM(k_enc)
        self._meta_aead: AESGCM | None = AESGCM(k_meta)

    @classmethod
    def derive(cls, dek: bytes, file_id: str) -> "FileKeys":
        """Derive the working keys from a 32-byte DEK and the file id."""
        if not isinstance(dek, (bytes, bytearray)) or len(dek) != DEK_BYTES:
            raise ValueError("data key must be exactly 32 bytes")
        fid = encode_file_id(file_id)
        dek = bytes(dek)
        return cls(file_id,
                   _derive(dek, LABEL_CHUNK_ENCRYPTION, fid),
                   _derive(dek, LABEL_MANIFEST_MAC, fid),
                   _derive(dek, LABEL_METADATA_ENCRYPTION, fid))

    # -- accessors ----------------------------------------------------------
    @property
    def file_id(self) -> str:
        return self._file_id

    @property
    def destroyed(self) -> bool:
        return self._k_enc is None

    def _get(self, value):
        if value is None:
            raise ValueError("file keys have been destroyed")
        return value

    @property
    def k_enc(self) -> bytes:
        return self._get(self._k_enc)

    @property
    def k_mac(self) -> bytes:
        return self._get(self._k_mac)

    @property
    def k_meta(self) -> bytes:
        return self._get(self._k_meta)

    @property
    def chunk_aead(self) -> AESGCM:
        return self._get(self._enc_aead)

    @property
    def metadata_aead(self) -> AESGCM:
        return self._get(self._meta_aead)

    # -- lifecycle ----------------------------------------------------------
    def destroy(self) -> None:
        """Drop all key references (best effort; see class docstring)."""
        self._k_enc = self._k_mac = self._k_meta = None
        self._enc_aead = self._meta_aead = None

    def __enter__(self) -> "FileKeys":
        return self

    def __exit__(self, *exc) -> None:
        self.destroy()

    def __repr__(self) -> str:
        state = "destroyed" if self.destroyed else "loaded"
        return f"FileKeys(file_id={self._file_id!r}, {state})"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("FileKeys cannot be pickled or copied")
