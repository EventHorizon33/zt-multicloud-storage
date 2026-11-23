"""Domain errors shared across modules. The API layer maps these to HTTP
responses; messages returned to clients are deliberately generic."""
from __future__ import annotations


class AppError(Exception):
    status_code = 500
    code = "internal-error"

    def __init__(self, message: str = "", *, reasons: tuple[str, ...] = ()):
        super().__init__(message or self.code)
        self.reasons = reasons


class AuthenticationError(AppError):       # 401: no/invalid/expired/revoked credentials
    status_code = 401
    code = "unauthenticated"


class AccessDenied(AppError):              # 403: policy decision = deny
    status_code = 403
    code = "access-denied"


class NotFound(AppError):                  # 404 (also used to hide existence where appropriate)
    status_code = 404
    code = "not-found"


class BadMultipart(AppError):              # 400: request body is not parseable multipart (I1)
    status_code = 400
    code = "bad-multipart"


class PayloadTooLarge(AppError):           # 413: a part of the request exceeds a parser limit
    status_code = 413
    code = "request-too-large"


class ValidationFailed(AppError):
    status_code = 422
    code = "validation-failed"


class Conflict(AppError):
    status_code = 409
    code = "conflict"


class RateLimited(AppError):
    status_code = 429
    code = "rate-limited"


class IntegrityError(AppError):
    """Chunk, manifest, or whole-file verification failed. Never deliver data."""
    status_code = 409
    code = "integrity-failure"


class ManifestIntegrityError(IntegrityError):
    code = "manifest-integrity-failure"


class ChunkIntegrityError(IntegrityError):
    code = "chunk-integrity-failure"


class DataUnavailable(AppError):
    """A required chunk has no retrievable, valid replica."""
    status_code = 503
    code = "data-unavailable"


class UploadFailed(AppError):
    status_code = 502
    code = "upload-failed"


class KmsError(AppError):
    code = "kms-error"
