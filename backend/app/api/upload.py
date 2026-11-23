"""Streaming multipart parser for uploads.

The request body is parsed incrementally with ``python_multipart`` and the
file part is handed to the (synchronous) file service as a pull-based
reader: each ``read`` in the worker thread pulls just enough of the request
stream through the event loop (``anyio.from_thread.run``). Nothing is
spooled to disk and memory stays bounded at roughly one chunk plus one
network read, so the 256 MiB upload cap does not mean 256 MiB of RAM.

Form layout: an optional ``classification`` text field, then exactly one
file part named ``file``. Text fields after the file part are ignored
(``classification`` may also be given as a query parameter).
"""
from __future__ import annotations

from typing import Any

import anyio.from_thread
from fastapi import Request
from python_multipart.exceptions import FormParserError
from python_multipart.multipart import MultipartParser, parse_options_header

from app.errors import BadMultipart, PayloadTooLarge, ValidationFailed

MAX_FIELD_BYTES = 1024
MAX_FIELDS = 8


class UploadAborted(Exception):
    """The request body ended before the file part was complete."""


def _parse_error(exc: Exception) -> Exception:
    """Finding I1: python_multipart parse errors are client errors, not 500s.
    Exceeded parser limits (part header size/count, boundary length) -> 413,
    anything else -> 400 ``bad-multipart``. The library message is not
    returned (it can quote request bytes)."""
    text = str(exc).lower()
    if "maximum" in text or "exceeds" in text or "too long" in text:
        return PayloadTooLarge("multipart part header too large", reasons=("multipart-limit-exceeded",))
    return BadMultipart("malformed multipart body", reasons=("bad-multipart",))


class StreamingMultipart:
    def __init__(self, request: Request) -> None:
        ctype, params = parse_options_header(request.headers.get("content-type", ""))
        if ctype != b"multipart/form-data" or b"boundary" not in params:
            raise ValidationFailed("multipart/form-data required", reasons=("multipart-required",))
        self._stream = request.stream().__aiter__()
        self._events: list[tuple[str, Any]] = []
        cb = {
            "on_part_begin": lambda: self._events.append(("begin", None)),
            "on_part_data": lambda d, s, e: self._events.append(("data", bytes(d[s:e]))),
            "on_part_end": lambda: self._events.append(("end", None)),
            "on_header_field": lambda d, s, e: self._events.append(("hfield", bytes(d[s:e]))),
            "on_header_value": lambda d, s, e: self._events.append(("hvalue", bytes(d[s:e]))),
            "on_header_end": lambda: self._events.append(("hend", None)),
            "on_headers_finished": lambda: self._events.append(("hdone", None)),
        }
        try:
            self._parser = MultipartParser(params[b"boundary"], cb)
        except FormParserError as exc:
            raise _parse_error(exc) from None
        self.fields: dict[str, str] = {}
        self.filename: str | None = None
        self.content_type: str | None = None
        self._buf = bytearray()
        self._part: str | None = None          # "field" | "file" | "skip"
        self._field_name = ""
        self._field_val = bytearray()
        self._hf = bytearray()
        self._hv = bytearray()
        self._headers: dict[bytes, bytes] = {}
        self._file_seen = False
        self.file_done = False
        self.eof = False

    # -- event-loop side ---------------------------------------------------- #
    def _process(self) -> None:
        for kind, data in self._events:
            if kind == "begin":
                self._headers, self._part = {}, None
            elif kind == "hfield":
                self._hf += data
            elif kind == "hvalue":
                self._hv += data
            elif kind == "hend":
                self._headers[bytes(self._hf).lower()] = bytes(self._hv)
                self._hf, self._hv = bytearray(), bytearray()
            elif kind == "hdone":
                _, disp = parse_options_header(self._headers.get(b"content-disposition", b""))
                name = disp.get(b"name", b"").decode("utf-8", "replace")
                if b"filename" in disp and name == "file" and not self._file_seen:
                    self._file_seen = True
                    self._part = "file"
                    raw = disp.get(b"filename", b"")
                    self.filename = raw.decode("utf-8", "replace")
                    self.content_type = self._headers.get(b"content-type", b"").decode("latin-1")
                elif b"filename" not in disp and not self._file_seen and len(self.fields) < MAX_FIELDS:
                    self._part, self._field_name, self._field_val = "field", name, bytearray()
                else:
                    self._part = "skip"
            elif kind == "data":
                if self._part == "file":
                    self._buf += data
                elif self._part == "field":
                    self._field_val += data
                    if len(self._field_val) > MAX_FIELD_BYTES:
                        raise ValidationFailed("form field too large", reasons=("field-too-large",))
            elif kind == "end":
                if self._part == "field":
                    self.fields[self._field_name] = bytes(self._field_val).decode("utf-8", "replace")
                elif self._part == "file":
                    self.file_done = True
                self._part = None
        self._events.clear()

    async def _pump(self) -> None:
        try:
            chunk = await self._stream.__anext__()
        except StopAsyncIteration:
            self.eof = True
            try:
                self._parser.finalize()
            except FormParserError as exc:
                raise _parse_error(exc) from None
            self._process()
            return
        if chunk:
            try:
                self._parser.write(chunk)
            except FormParserError as exc:
                raise _parse_error(exc) from None
            self._process()

    async def start(self) -> None:
        """Parse up to the start of the file part (collecting text fields)."""
        while not self._file_seen and not self.eof:
            await self._pump()
        if not self._file_seen:
            raise ValidationFailed("no file part", reasons=("file-missing",))

    async def _fill(self, n: int) -> None:
        while len(self._buf) < n and not self.file_done and not self.eof:
            await self._pump()

    # -- worker-thread side ------------------------------------------------- #
    def read(self, n: int = -1) -> bytes:
        """Blocking read for the file service (call only from a worker thread
        started with ``anyio.to_thread``)."""
        want = n if n is not None and n >= 0 else 1 << 62
        if len(self._buf) < want and not self.file_done:
            anyio.from_thread.run(self._fill, want)
            if len(self._buf) == 0 and not self.file_done:
                raise UploadAborted("request body ended inside the file part")
        out = bytes(self._buf[:want])
        del self._buf[:want]
        return out
