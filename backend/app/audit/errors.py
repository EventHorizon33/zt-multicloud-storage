"""Errors raised by the audit subsystem. Messages are deliberately generic:
they never contain SQL, parameters, connection strings or event contents."""
from __future__ import annotations

from app.errors import AppError


class AuditError(AppError):
    status_code = 500
    code = "audit-error"


class AuditWriteError(AuditError):
    """The event could not be durably written. Callers must treat this as
    "the operation cannot be audited and therefore must not proceed"."""
    status_code = 503
    code = "audit-unavailable"


class AuditIntegrityError(AuditError):
    """An operation that would destroy evidence (retention) was refused because
    the part of the chain it would delete does not verify."""
    status_code = 409
    code = "audit-integrity-failure"
