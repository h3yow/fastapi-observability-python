"""Correlation-id context propagation.

A single correlation id is bound at request entry and travels unchanged
through synchronous handlers, thread-pool handlers, background tasks and
downstream calls. Isolation between concurrent requests is provided by
:class:`contextvars.ContextVar` (each asyncio task / worker thread receives
its own copy of the context).

Inbound rule (deterministic):
* header ``X-Request-Id`` is reused **only** when it matches
  :data:`INCOMING_ID_PATTERN` (8-128 chars, ``[A-Za-z0-9]`` first, then
  ``[A-Za-z0-9._-]``);
* a missing, empty or malformed value is replaced by a freshly generated id.
"""
from __future__ import annotations

import contextvars
import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

#: header used both for inbound reuse and outbound propagation
HEADER_NAME = "x-request-id"

#: accepted shape of a caller-supplied correlation id
INCOMING_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{7,127}$")

#: per-request correlation id; "" means "unset in this context"
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "request_id", default=""
)


def new_request_id() -> str:
    """Generate a new correlation id (32 lowercase hex chars)."""
    return uuid.uuid4().hex


def is_valid_incoming_id(raw: str | None) -> bool:
    """Return True iff *raw* may be reused as a correlation id."""
    if not raw:
        return False
    candidate = raw.strip()
    return bool(INCOMING_ID_PATTERN.fullmatch(candidate))


def resolve_incoming_id(raw: str | None) -> tuple[str, bool]:
    """Resolve the id for an inbound request.

    Returns ``(request_id, reused)``. ``reused`` is True when the caller
    value was accepted verbatim, False when a new id was minted.
    """
    if raw is not None:
        candidate = raw.strip()
        if INCOMING_ID_PATTERN.fullmatch(candidate):
            return candidate, True
    return new_request_id(), False


def get_request_id() -> str:
    """Return the current correlation id (never None; "" if unbound)."""
    return request_id_var.get()


def set_request_id(value: str) -> contextvars.Token[str]:
    """Bind *value* in the current context; returns the reset token."""
    return request_id_var.set(value)


def reset_request_id(token: contextvars.Token[str]) -> None:
    """Undo a previous :func:`set_request_id`."""
    request_id_var.reset(token)


@contextmanager
def bind_request_id(value: str) -> Iterator[None]:
    """Bind *value* for the duration of the ``with`` block."""
    token = set_request_id(value)
    try:
        yield
    finally:
        reset_request_id(token)
