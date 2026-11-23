"""Composition root: builds every subsystem from ``Settings`` and wires them
together through the contracts in ``app/contracts.py``.

Security-relevant wiring decisions made here:
  * ONE clock (aware UTC) is shared by auth, policy, audit, detection and the
    file service, so token expiry, MFA freshness, audit timestamps and
    detection windows agree (and tests can advance time consistently).
  * The audit service is built first and is the ``AuditSink`` of every other
    subsystem. Its anchor store is the storage orchestrator (through
    ``OrchestratorAnchorStore``), so signed checkpoints land on every provider.
  * The audit allow-list is extended with the detail keys the other
    subsystems actually emit (``EXTRA_AUDIT_DETAILS``); a test asserts that
    nothing an integrated flow records gets dropped.
  * ``policy.change`` details are flattened by ``_PolicyAuditAdapter``: the
    policy store emits ``{"changes": {key: {"old", "new"}}}`` (two levels),
    which the audit privacy filter (one level only, by design) would drop.
"""
from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from sqlalchemy import Engine
from sqlalchemy.orm import Session as DbSession, sessionmaker

from app.admin import AdminService
from app.audit import AuditService, build_audit_service
from app.auth import AuthService, PasswordHasher
from app.config import Settings
from app.contracts import KeyManagementService, StorageProvider
from app.cryptoengine import CryptoEngine
from app.db import init_db, make_engine, make_session_factory
from app.detection import AuthFailureDetector, DownloadDetector
from app.errors import AppError
from app.files.service import FileService
from app.kms import build_kms
from app.policy import PolicyConfig, PolicyDecisionPoint, PolicyEnforcementPoint, PolicyStore
from app.ratelimit import RateLimitAuditor, RateLimiter, TokenFailureAuditor
from app.storage import HealthMonitor, StorageMetrics, StorageOrchestrator, build_orchestrator, build_providers

log = logging.getLogger("zt.container")

Clock = Callable[[], datetime]


def utc_clock() -> datetime:
    return datetime.now(timezone.utc)


#: Detail keys emitted by the subsystems that are not in the audit module's
#: GLOBAL_ALLOWED_DETAIL_KEYS (see each package's NOTES.md).
EXTRA_AUDIT_DETAILS: dict[str, frozenset[str]] = {
    # app/auth
    "auth.*": frozenset({"failed_count", "lockout_seconds", "sessions_revoked", "sessions_kept",
                         "reuse_suspected", "scope"}),
    # app/policy (policy.change)
    "policy.*": frozenset({"changes", "version"}),
    # app/storage orchestrator + health monitor
    "chunk.*": frozenset({"outcomes"}),
    "storage.*": frozenset({"outcomes", "healthy", "consecutive_failures", "injected"}),
    # app/detection
    "security.*": frozenset({"block_seconds", "distinct_accounts", "scope"}),
    # app/files
    "file.*": frozenset({"leftover_replicas", "unavailable", "chunks_repaired", "chunks_unrepairable",
                         "status", "shares_revoked"}),
    # app/api admin actions
    "admin.*": frozenset({"old_clearance", "new_clearance", "active", "cidr_count", "sessions_revoked",
                          "files_rewrapped", "rewrap_failures"}),
}


class OrchestratorAnchorStore:
    """Adapts ``StorageOrchestrator``'s anchor API to ``app.audit.AnchorStore``.

    Bound late (``bind``) because the orchestrator itself needs the audit
    service as its sink. Until bound, every call raises, which the audit
    service records as an anchor failure rather than an exception."""

    def __init__(self) -> None:
        self._orch: StorageOrchestrator | None = None

    def bind(self, orchestrator: StorageOrchestrator) -> None:
        self._orch = orchestrator

    def _o(self) -> StorageOrchestrator:
        if self._orch is None:
            raise RuntimeError("anchor store not bound")
        return self._orch

    def put_anchor(self, key: str, data: bytes) -> dict[str, bool]:
        res = self._o().put_anchor(key, data)
        out = {name: True for name in res.stored_on}
        out.update({f.provider: False for f in res.failed})
        return out

    def get_anchor(self, key: str) -> dict[str, bytes | None]:
        reads = self._o().get_anchor(key)
        if reads and all(r.outcome not in ("ok", "missing") for r in reads.values()):
            # no provider answered: "unavailable", not "missing everywhere"
            raise RuntimeError("no provider could be read")
        return {name: (r.data if r.outcome == "ok" else None)
                for name, r in reads.items() if r.outcome in ("ok", "missing")}

    def list_anchors(self, prefix: str) -> dict[str, list[str]]:
        listing = self._o().list_anchors(prefix)
        if not listing.keys and listing.errors:
            raise RuntimeError("no provider could be listed")
        return {name: list(keys) for name, keys in listing.keys.items()}


class _PolicyAuditAdapter:
    """AuditSink wrapper for the PolicyStore only: flattens
    ``details["changes"][key] = {"old": x, "new": y}`` into the string
    ``"<old json> -> <new json>"`` so the one-level audit filter keeps it."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def record(self, **kwargs: Any) -> Any:
        details = kwargs.get("details")
        if isinstance(details, Mapping) and isinstance(details.get("changes"), Mapping):
            flat = {}
            for key, val in details["changes"].items():
                if isinstance(val, Mapping) and {"old", "new"} <= set(val):
                    flat[str(key)] = (json.dumps(val["old"], separators=(",", ":"), sort_keys=True)
                                      + " -> " + json.dumps(val["new"], separators=(",", ":"), sort_keys=True))
                else:
                    flat[str(key)] = json.dumps(val, separators=(",", ":"), sort_keys=True, default=str)
            kwargs["details"] = {**details, "changes": flat}
        return self._inner.record(**kwargs)


@dataclass
class Container:
    settings: Settings
    clock: Clock
    kms: KeyManagementService
    audit: AuditService
    anchor_store: OrchestratorAnchorStore
    providers: dict[str, StorageProvider]
    metrics: StorageMetrics
    health: HealthMonitor
    orchestrator: StorageOrchestrator
    engine: Engine
    session_factory: sessionmaker[DbSession]
    crypto: CryptoEngine
    auth: AuthService
    policy_store: PolicyStore
    pdp: PolicyDecisionPoint
    pep: PolicyEnforcementPoint
    rate_limiter: RateLimiter
    download_detector: DownloadDetector
    auth_failure_detector: AuthFailureDetector
    files: FileService
    admin: AdminService
    rate_limit_auditor: RateLimitAuditor | None = None
    token_failure_auditor: TokenFailureAuditor | None = None
    background: bool = True
    maintenance_interval_seconds: float = 60.0
    _stop: threading.Event = field(default_factory=threading.Event)
    _maint: threading.Thread | None = None
    started: bool = False

    # ------------------------------------------------------------------ #
    @classmethod
    def build(cls, settings: Settings, *, clock: Clock | None = None,
              providers: dict[str, StorageProvider] | None = None,
              password_hasher: PasswordHasher | None = None,
              kms: KeyManagementService | None = None,
              background: bool = True,
              stale_upload_minutes: float = 10.0) -> "Container":
        clock = clock or utc_clock
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        if kms is None:
            kms = build_kms(settings)
            ensure = getattr(kms, "ensure_keys", None)
            if callable(ensure):
                ensure()
        anchor_store = OrchestratorAnchorStore()
        audit = build_audit_service(settings, kms, anchor_store, clock,
                                    extra_allowed_details=EXTRA_AUDIT_DETAILS)
        providers = providers if providers is not None else build_providers(settings)
        metrics = StorageMetrics()
        health = HealthMonitor(providers, interval=settings.health_check_interval_seconds, audit=audit)
        orchestrator = build_orchestrator(settings, providers=providers, audit=audit, health=health,
                                          metrics=metrics)
        anchor_store.bind(orchestrator)

        engine = make_engine(settings.database_url)
        init_db(engine)
        session_factory = make_session_factory(engine)

        crypto = CryptoEngine(kms, settings.chunk_size_bytes)
        auth = AuthService(settings=settings, kms=kms, audit=audit, clock=clock,
                           password_hasher=password_hasher)
        policy_store = PolicyStore(settings=settings, audit=_PolicyAuditAdapter(audit), clock=clock)
        pdp = PolicyDecisionPoint(PolicyConfig.from_settings(settings))
        pep = PolicyEnforcementPoint(pdp, audit, policy_store)
        rate_limiter = RateLimiter()
        rate_limit_auditor = RateLimitAuditor(audit=audit, clock=clock, window_seconds=60)
        token_failure_auditor = TokenFailureAuditor(audit=audit, clock=clock, window_seconds=60)
        auth.token_failure_gate = token_failure_auditor.admit          # M2
        download_detector = DownloadDetector(audit=audit, clock=clock)
        auth_failure_detector = AuthFailureDetector(
            audit=audit, clock=clock, window_seconds=settings.detect_window_seconds,
            prefix_v4=settings.audit_ip_prefix_v4, prefix_v6=settings.audit_ip_prefix_v6)
        files = FileService(settings=settings, crypto=crypto, orchestrator=orchestrator, pep=pep,
                            audit=audit, detector=download_detector, policy_store=policy_store,
                            clock=clock, stale_upload_minutes=stale_upload_minutes)
        admin = AdminService(pep=pep, audit=audit, auth=auth, kms=kms, files=files, clock=clock,
                             policy_store=policy_store)
        return cls(settings=settings, clock=clock, kms=kms, audit=audit, anchor_store=anchor_store,
                   providers=providers, metrics=metrics, health=health, orchestrator=orchestrator,
                   engine=engine, session_factory=session_factory, crypto=crypto, auth=auth,
                   policy_store=policy_store, pdp=pdp, pep=pep, rate_limiter=rate_limiter,
                   download_detector=download_detector, auth_failure_detector=auth_failure_detector,
                   files=files, admin=admin, rate_limit_auditor=rate_limit_auditor,
                   token_failure_auditor=token_failure_auditor, background=background)

    # ------------------------------------------------------------------ #
    def db(self) -> DbSession:
        return self.session_factory()

    def start(self) -> None:
        """Bootstrap admin, crash recovery, then background threads."""
        if self.started:
            return
        s = self.settings
        if s.bootstrap_admin_username and s.bootstrap_admin_password:
            with self.db() as db:
                try:
                    self.auth.ensure_bootstrap_admin(db, s.bootstrap_admin_username,
                                                     s.bootstrap_admin_password)
                except AppError as exc:
                    # fail fast with a clear, secret-free message
                    raise RuntimeError("bootstrap admin could not be created: "
                                       f"{exc.code} {list(exc.reasons)}") from None
        self.run_maintenance()
        try:
            self.health.check_all()      # know provider state before the first request
        except Exception:  # pragma: no cover
            log.warning("initial provider health probe failed")
        if self.background:
            self.health.start()
            self._stop.clear()
            self._maint = threading.Thread(target=self._maintenance_loop, name="zt-maintenance",
                                           daemon=True)
            self._maint.start()
        self.started = True

    def run_maintenance(self) -> dict[str, int]:
        """Recover stale uploads / interrupted deletes, retry leftover
        replica deletes, prune detection records. Never raises."""
        out: dict[str, int] = {}
        try:
            with self.db() as db:
                out = self.files.recover(db)
                cfg = self.policy_store.load(db)
                out["download_records_pruned"] = self.download_detector.prune(db, cfg.window_seconds)
            if self.rate_limit_auditor is not None:
                out["rate_limit_summaries"] = self.rate_limit_auditor.flush()
            if self.token_failure_auditor is not None:
                out["token_failure_summaries"] = self.token_failure_auditor.flush()
        except Exception as exc:  # pragma: no cover - logged, retried next round
            log.warning("maintenance run failed: %s", type(exc).__name__)
        return out

    def _maintenance_loop(self) -> None:
        while not self._stop.wait(self.maintenance_interval_seconds):
            self.run_maintenance()

    def stop(self) -> None:
        self._stop.set()
        if self._maint is not None:
            self._maint.join(timeout=5)
            self._maint = None
        try:
            if self.health.running:
                self.health.stop()
        except Exception:  # pragma: no cover
            pass
        try:
            if self.rate_limit_auditor is not None:
                self.rate_limit_auditor.flush(force=True)   # do not lose suppressed 429 counts
            if self.token_failure_auditor is not None:
                self.token_failure_auditor.flush(force=True)
        except Exception:  # pragma: no cover
            pass
        self.orchestrator.close()
        self.audit.close()
        self.engine.dispose()
        self.started = False
