"""Stable external error codes and exception mapping.

Every failure returned to callers uses one shared envelope::

    {"error": {"code": "...", "message": "...", "request_id": "...",
               "details": {...optional...}}}

Codes are stable strings (never raw exception text), so clients can branch
on them and so logs/metrics/responses can be correlated. The original
exception is still logged server-side with its full chain.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.context import get_request_id
from app.sanitize import sanitize

#: external error code constants
VALIDATION_ERROR = "VALIDATION_ERROR"
NOT_FOUND = "NOT_FOUND"
METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
UPSTREAM_ERROR = "UPSTREAM_ERROR"
INTERNAL_ERROR = "INTERNAL_ERROR"

#: code -> (http status, stable human-readable message)
ERROR_TABLE: dict[str, tuple[int, str]] = {
    VALIDATION_ERROR: (422, "Request validation failed"),
    NOT_FOUND: (404, "Route not found"),
    METHOD_NOT_ALLOWED: (405, "Method not allowed"),
    UPSTREAM_ERROR: (502, "Downstream call failed"),
    INTERNAL_ERROR: (500, "Internal server error"),
}


@dataclass(frozen=True)
class ErrorCode:
    code: str
    status: int
    message: str

    @classmethod
    def get(cls, code: str) -> "ErrorCode":
        status, message = ERROR_TABLE[code]
        return cls(code=code, status=status, message=message)


VALIDATION = ErrorCode.get(VALIDATION_ERROR)
NOT_FOUND_ERR = ErrorCode.get(NOT_FOUND)
METHOD_NOT_ALLOWED_ERR = ErrorCode.get(METHOD_NOT_ALLOWED)
UPSTREAM = ErrorCode.get(UPSTREAM_ERROR)
INTERNAL = ErrorCode.get(INTERNAL_ERROR)


def error_body(code: ErrorCode, *, details: Any | None = None) -> dict[str, Any]:
    """Build the canonical external error envelope.

    *details* (if given) is run through the sanitizer before inclusion so
    error responses can never leak credentials or personal data.
    """
    error: dict[str, Any] = {
        "code": code.code,
        "message": code.message,
        "request_id": get_request_id(),
    }
    if details is not None:
        error["details"] = sanitize(details)
    return {"error": error}
