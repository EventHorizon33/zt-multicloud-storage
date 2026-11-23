"""ASGI entry point.

    uvicorn app.main:app            (settings from ZT_* environment / .env)

``create_app(settings, container=None)`` is the factory used by tests. The
module attribute ``app`` is created lazily on first access so that importing
this module never needs configuration.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import (routes_admin, routes_audit, routes_auth, routes_dashboard, routes_files, routes_security,
                     routes_storage)
from app.api.errors import install_error_handlers
from app.api.logging_setup import configure_logging
from app.api.middleware import AppMiddleware, RequestCounters
from app.config import Settings, get_settings
from app.container import Container

API_VERSION = "1.0.0"


def create_app(settings: Settings | None = None, *, container: Container | None = None,
               **container_kwargs: Any) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    container = container or Container.build(settings, **container_kwargs)
    # M4: interactive docs and the OpenAPI schema only outside production
    # (Settings validates env to production | development | test, default production).
    docs = settings.env != "production"

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        container.start()
        try:
            yield
        finally:
            container.stop()

    app = FastAPI(title="Zero-Trust Multi-Cloud Chunked Storage API", version=API_VERSION, lifespan=lifespan,
                  docs_url="/docs" if docs else None, redoc_url="/redoc" if docs else None,
                  openapi_url="/openapi.json" if docs else None)
    app.state.container = container
    app.state.counters = RequestCounters()
    install_error_handlers(app)
    for r in (routes_auth.router, routes_files.router, routes_storage.router, routes_audit.router,
              routes_security.router, routes_admin.router, routes_dashboard.router):
        app.include_router(r)
    if settings.enable_fault_injection and settings.env != "production":
        app.include_router(routes_storage.fault_router)
    app.add_middleware(AppMiddleware, settings=settings, counters=app.state.counters, docs_enabled=docs)
    app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_credentials=True,
                       allow_methods=["GET", "POST", "PUT", "DELETE"],
                       allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
                       expose_headers=["Content-Disposition", "X-Request-ID", "X-Client-Request-ID", "X-Content-SHA256",
                                       "Retry-After"],
                       max_age=600)
    return app


_app: FastAPI | None = None


def __getattr__(name: str) -> Any:
    global _app
    if name == "app":
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(name)
