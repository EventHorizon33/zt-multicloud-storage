"""Structured JSON application logging with redaction.

Security property: every log line passes ``redact`` before it is written, so
bearer tokens, JWTs, cookie / Authorization headers and ``password=``-style
assignments are masked even if a developer logs them by mistake. The app
code itself never logs tokens, passwords, TOTP codes, filenames or file
content (CONTRACTS rule 4); redaction is the second line of defence.
"""
from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone

_PATTERNS = [
    (re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), "[REDACTED-JWT]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|refresh_token|access_token|totp_code|code|cookie|"
                r"authorization|api_key|accountkey)\s*[=:]\s*(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)zt_refresh=[^;\s]+"), "zt_refresh=[REDACTED]"),
]

_RESERVED = set(vars(logging.LogRecord("x", 0, "x", 0, "", None, None)).keys()) | {"message", "asctime"}


def redact(text: str) -> str:
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact(record.getMessage()),
        }
        for key, value in vars(record).items():
            if key not in _RESERVED and not key.startswith("_"):
                out[key] = redact(value) if isinstance(value, str) else value
        if record.exc_info and record.exc_info[0] is not None:
            # exception class + location only: messages and locals can hold secrets
            tb = record.exc_info[2]
            while tb is not None and tb.tb_next is not None:
                tb = tb.tb_next
            out["exc_type"] = record.exc_info[0].__name__
            if tb is not None:
                out["exc_at"] = f"{tb.tb_frame.f_code.co_filename.rsplit('/', 1)[-1]}:{tb.tb_lineno}"
        return json.dumps(out, default=str, ensure_ascii=True)


_configured = False


def configure_logging(level: str = "INFO") -> None:
    """Install the JSON handler on the ``zt`` logger tree and uvicorn's loggers (idempotent)."""
    global _configured
    lvl = getattr(logging, str(level).upper(), logging.INFO)
    if _configured:
        logging.getLogger("zt").setLevel(lvl)
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    for name in ("zt", "app", "uvicorn", "uvicorn.error"):
        lg = logging.getLogger(name)
        lg.handlers = [handler]
        lg.setLevel(lvl)
        lg.propagate = False
    # uvicorn's access log prints raw paths + query strings: our middleware logs instead
    logging.getLogger("uvicorn.access").disabled = True
    _configured = True
