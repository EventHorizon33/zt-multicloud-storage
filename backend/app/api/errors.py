"""Error mapping: every error becomes ``{"error", "reasons", "request_id"}``
(+ ``obligations`` for policy denials). Messages are generic codes; internal
exception text is never returned.

401 responses never echo token/session failure reasons (they would help an
attacker probe tokens); the only reasons a 401 may carry are the login
prompts ``mfa-required`` / ``mfa-invalid``, which the auth service emits only
after a correct password."""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.middleware import BodyTooLarge
from app.errors import AppError, AuthenticationError, RateLimited, ValidationFailed

log = logging.getLogger("zt.api")

_CLIENT_SAFE_401 = {"mfa-required", "mfa-invalid"}
_HTTP_CODES = {400: "bad-request", 401: "unauthenticated", 403: "access-denied", 404: "not-found",
               405: "method-not-allowed", 406: "not-acceptable", 409: "conflict", 413: "request-too-large",
               415: "unsupported-media-type", 422: "validation-failed", 429: "rate-limited"}


def _rid(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def error_body(request: Request, code: str, reasons=(), **extra) -> dict:
    body = {"error": code, "reasons": list(reasons), "request_id": _rid(request)}
    body.update({k: v for k, v in extra.items() if v})
    return body


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError):
        reasons = tuple(getattr(exc, "reasons", ()) or ())
        status = exc.status_code
        code = exc.code
        if isinstance(exc, AuthenticationError):
            reasons = tuple(r for r in reasons if r in _CLIENT_SAFE_401)
            code = "unauthenticated"
        if isinstance(exc, ValidationFailed) and "upload-too-large" in reasons:
            status, code = 413, "request-too-large"
        headers = {}
        if isinstance(exc, RateLimited):
            headers["Retry-After"] = str(max(1, int(getattr(exc, "retry_after_seconds", 1) or 1)))
        if isinstance(exc, AuthenticationError):
            headers["WWW-Authenticate"] = "Bearer"
        if status >= 500:
            log.warning("request failed", extra={"request_id": _rid(request), "error": code})
        obligations = list(getattr(exc, "obligations", ()) or ())
        return JSONResponse(error_body(request, code, reasons, obligations=obligations), status_code=status,
                            headers=headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        reasons = []
        for err in exc.errors()[:20]:
            loc = ".".join(str(p) for p in err.get("loc", ()) if p != "body")
            reasons.append(f"{loc}:{err.get('type', 'invalid')}"[:128])
        return JSONResponse(error_body(request, "validation-failed", reasons), status_code=422)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        code = _HTTP_CODES.get(exc.status_code, "error")
        return JSONResponse(error_body(request, code), status_code=exc.status_code,
                            headers=getattr(exc, "headers", None))

    @app.exception_handler(BodyTooLarge)
    async def _too_large(request: Request, exc: BodyTooLarge):
        return JSONResponse(error_body(request, "request-too-large"), status_code=413)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        log.error("unhandled error", exc_info=exc, extra={"request_id": _rid(request)})
        return JSONResponse(error_body(request, "internal-error"), status_code=500)
