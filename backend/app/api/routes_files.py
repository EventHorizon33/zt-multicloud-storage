"""/api/files and /api/admin/files. Thin HTTP layer over ``FileService``
(all decisions are made by the PEP inside the service)."""
from __future__ import annotations

import re
import unicodedata
from typing import Iterator
from urllib.parse import quote

import anyio.to_thread
from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import StreamingResponse

from app.api.deps import Caller, get_caller, rate_limit
from app.api.schemas import ShareIn
from app.api.upload import StreamingMultipart
from app.contracts import Role

router = APIRouter(tags=["files"])

_ASCII_SAFE = re.compile(r"[^A-Za-z0-9._ ()+-]")
_STREAM_BLOCK = 64 * 1024


def content_disposition(filename: str) -> str:
    """RFC 6266 attachment header: an ASCII fallback with every unsafe
    character replaced, plus the exact name percent-encoded in ``filename*``.
    Quotes, backslashes, CR/LF and ``;`` can never break out of the header."""
    ascii_name = unicodedata.normalize("NFKD", filename).encode("ascii", "ignore").decode("ascii")
    ascii_name = _ASCII_SAFE.sub("_", ascii_name).strip() or "download"
    return f"attachment; filename=\"{ascii_name[:150]}\"; filename*=UTF-8''{quote(filename, safe='')}"


@router.post("/api/files", status_code=201)
async def upload_file(request: Request, classification: str | None = Query(default=None, max_length=16),
                      caller: Caller = Depends(get_caller)) -> dict:
    c = caller.container
    rate_limit(request, "upload", caller.user.id, c.settings.rate_limit_upload_per_minute)
    form = StreamingMultipart(request)
    await form.start()
    cls = classification if classification is not None else form.fields.get("classification")
    return await anyio.to_thread.run_sync(lambda: c.files.upload(
        caller.db, caller.subject, form, filename=form.filename, mime_type=form.content_type,
        classification=cls, context=caller.context))


@router.get("/api/files")
def list_files(caller: Caller = Depends(get_caller)) -> dict:
    files = caller.container.files.list_files(caller.db, caller.subject, caller.context)
    return {"files": files, "total": len(files)}


@router.get("/api/files/{file_id}")
def file_metadata(file_id: str, caller: Caller = Depends(get_caller)) -> dict:
    return caller.container.files.get_metadata(caller.db, caller.subject, file_id, caller.context)


@router.get("/api/files/{file_id}/download")
def download_file(file_id: str, request: Request, caller: Caller = Depends(get_caller)) -> StreamingResponse:
    c = caller.container
    rate_limit(request, "download", caller.user.id, c.settings.rate_limit_download_per_minute)
    handle = c.files.download(caller.db, caller.subject, file_id, caller.context)

    def body() -> Iterator[bytes]:
        try:
            while True:
                block = handle.stream.read(_STREAM_BLOCK)
                if not block:
                    break
                yield block
        finally:
            handle.stream.close()

    headers = {"Content-Disposition": content_disposition(handle.filename),
               "Content-Length": str(handle.size_bytes),
               "X-Content-SHA256": handle.plaintext_sha256}
    return StreamingResponse(body(), media_type="application/octet-stream", headers=headers)


@router.delete("/api/files/{file_id}")
def delete_file(file_id: str, caller: Caller = Depends(get_caller)) -> dict:
    return caller.container.files.delete(caller.db, caller.subject, file_id, caller.context)


@router.get("/api/files/{file_id}/shares")
def list_shares(file_id: str, caller: Caller = Depends(get_caller)) -> dict:
    return {"shares": caller.container.files.list_shares(caller.db, caller.subject, file_id, caller.context)}


@router.post("/api/files/{file_id}/shares", status_code=201)
def share_file(file_id: str, body: ShareIn, caller: Caller = Depends(get_caller)) -> dict:
    return caller.container.files.share(caller.db, caller.subject, file_id, body.username, caller.context)


@router.delete("/api/files/{file_id}/shares/{username}", status_code=204)
def unshare_file(file_id: str, username: str, caller: Caller = Depends(get_caller)) -> Response:
    caller.container.files.unshare(caller.db, caller.subject, file_id, username[:64], caller.context)
    return Response(status_code=204)


def _verify_rate(request: Request, caller: Caller) -> None:
    """L6: verify and repair re-download every replica of every chunk from
    the providers (egress cost, provider load), so they share one per-user
    budget (``rate_limit_verify_per_minute``, default 6)."""
    rate_limit(request, "verify", caller.user.id,
               int(getattr(caller.container.settings, "rate_limit_verify_per_minute", 6)))


@router.post("/api/files/{file_id}/verify")
def verify_file(file_id: str, request: Request, caller: Caller = Depends(get_caller)) -> dict:
    _verify_rate(request, caller)
    return caller.container.files.verify(caller.db, caller.subject, file_id, caller.context)


@router.post("/api/files/{file_id}/repair")
def repair_file(file_id: str, request: Request, caller: Caller = Depends(get_caller)) -> dict:
    _verify_rate(request, caller)
    return caller.container.files.repair(caller.db, caller.subject, file_id, caller.context)


@router.get("/api/files/{file_id}/distribution")
def file_distribution(file_id: str, caller: Caller = Depends(get_caller)) -> dict:
    return caller.container.files.distribution(caller.db, caller.subject, file_id, caller.context)


@router.get("/api/admin/files")
def admin_files(limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0, le=2**63 - 1),
                caller: Caller = Depends(get_caller)) -> dict:
    files, total = caller.container.files.admin_list_files(caller.db, caller.subject, caller.context,
                                                           limit=limit, offset=offset)
    return {"files": files, "total": total, "limit": limit, "offset": offset,
            "scope": "all" if caller.subject.role is Role.ADMIN else "own"}
