"""Privacy-aware, tamper-evident audit logging (Phase 5).

Public entry point: ``build_audit_service``. See ``NOTES.md`` in this
package for the API, record/checkpoint/anchor formats and stated limits.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Mapping

from app.audit.context import begin_request, bind_actor, current_audit_context, end_request, suspended
from app.audit.errors import AuditError, AuditIntegrityError, AuditWriteError
from app.audit.models import init_audit_db, make_audit_engine
from app.audit.privacy import (
    EVENT_ALLOWED_DETAIL_KEYS, GLOBAL_ALLOWED_DETAIL_KEYS, filter_details, generalise_ip,
)
from app.audit.records import (
    AuditContext, AuditRecord, Checkpoint, Finding, RetentionResult, VerificationReport,
)
from app.audit.service import AnchorStore, AuditService
from app.config import Settings
from app.contracts import KeyManagementService


def build_audit_service(
    settings: Settings,
    kms: KeyManagementService,
    anchor_store: AnchorStore | None = None,
    clock: Callable[[], datetime] | None = None,
    *,
    extra_allowed_details: Mapping[str, Any] | None = None,
) -> AuditService:
    """Create the audit engine on ``settings.audit_database_url`` (a database
    separate from the metadata DB), create the tables, and return the
    service."""
    engine = make_audit_engine(settings.audit_database_url)
    init_audit_db(engine)
    return AuditService(settings, kms, engine, anchor_store=anchor_store, clock=clock,
                        extra_allowed_details=extra_allowed_details)


__all__ = [
    "AnchorStore", "AuditContext", "AuditError", "AuditIntegrityError", "AuditRecord",
    "AuditService", "AuditWriteError", "Checkpoint", "EVENT_ALLOWED_DETAIL_KEYS",
    "Finding", "GLOBAL_ALLOWED_DETAIL_KEYS", "RetentionResult", "VerificationReport",
    "begin_request", "bind_actor", "build_audit_service", "current_audit_context", "end_request",
    "filter_details", "generalise_ip", "suspended",
]
