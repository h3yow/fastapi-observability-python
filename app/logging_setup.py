"""Structured JSON logging with correlation-id injection and masking.

Every log line is a single JSON object containing the current
``request_id`` (looked up from the context variable at emit time, so
background tasks and downstream calls share the id of the originating
request). ``extra_fields`` attached to records are sanitized before
serialization, so even accidental logging of request bodies cannot leak
credentials or personal data.
"""
from __future__ import annotations

import datetime as _dt
import json
import logging
import sys
from typing import Any

from app.context import get_request_id
from app.sanitize import sanitize

#: log-record attribute names we always emit verbatim
_RESERVED = set(logging.LogRecord(
    name="", level=0, pathname="", lineno=0, msg="", args=None, exc_info=None
).__dict__.keys()) | {"message", "asctime", "extra_fields"}


class RequestContextFilter(logging.Filter):
    """Attach the active correlation id to every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id()
        return True


class JsonFormatter(logging.Formatter):
    """Serialize records as one JSON object per line, sanitizing payloads."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": _dt.datetime.fromtimestamp(record.created).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname.lower(),
            "logger": record.name,
            "request_id": getattr(record, "request_id", ""),
            "message": record.getMessage(),
        }

        extra = getattr(record, "extra_fields", None)
        if extra:
            payload.update(sanitize(dict(extra)))

        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(level: int = logging.INFO) -> None:
    """Install the JSON handler on the root logger (idempotent)."""
    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        if getattr(handler, "_observability_handler", False):
            return  # already configured
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RequestContextFilter())
    handler._observability_handler = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    # transport libraries are noisy at INFO and emit outside the request
    # context (so their lines carry no correlation id); keep warnings only
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a logger under the configured root setup."""
    return logging.getLogger(name)
