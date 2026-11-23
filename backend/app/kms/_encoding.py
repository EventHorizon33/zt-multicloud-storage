"""Unambiguous byte encodings shared by the KMS implementations.

Nothing here is cryptography: these helpers only turn structured values into
byte strings in exactly one way, so that two different inputs can never
produce the same associated data (no concatenation ambiguity).
"""
from __future__ import annotations

import struct
from typing import Mapping

from app.errors import KmsError

MAX_CONTEXT_ENTRIES = 32
MAX_CONTEXT_ITEM_BYTES = 1024


def lp(data: bytes) -> bytes:
    """Length-prefix ``data`` with a 4-byte big-endian length."""
    return struct.pack(">I", len(data)) + data


def validate_context(context: Mapping[str, str]) -> dict[str, str]:
    """Return a plain ``dict`` copy of ``context`` after checking that it is a
    small mapping of ``str`` to ``str``. Raises :class:`KmsError` otherwise.

    Security property: a context that cannot be encoded canonically is
    rejected rather than coerced, so the wrap side and the unwrap side can
    never disagree about what was bound.
    """
    if not isinstance(context, Mapping):
        raise KmsError("context must be a mapping of str to str")
    if len(context) > MAX_CONTEXT_ENTRIES:
        raise KmsError("context has too many entries")
    out: dict[str, str] = {}
    for key, value in context.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise KmsError("context keys and values must be str")
        if not key:
            raise KmsError("context keys must be non-empty")
        try:
            kb, vb = key.encode("utf-8"), value.encode("utf-8")
        except UnicodeEncodeError:
            raise KmsError("context must be valid unicode") from None
        if len(kb) > MAX_CONTEXT_ITEM_BYTES or len(vb) > MAX_CONTEXT_ITEM_BYTES:
            raise KmsError("context item too long")
        out[key] = value
    return out


def canonical_context(context: Mapping[str, str]) -> bytes:
    """Canonical encoding of an encryption context.

    ``u32 count`` followed by, for each key in sorted (code point) order,
    ``u32 len || key utf-8 || u32 len || value utf-8``. Insertion order of the
    mapping does not matter; any difference in keys or values changes the
    output.
    """
    ctx = validate_context(context)
    parts = [struct.pack(">I", len(ctx))]
    for key in sorted(ctx):
        parts.append(lp(key.encode("utf-8")))
        parts.append(lp(ctx[key].encode("utf-8")))
    return b"".join(parts)
