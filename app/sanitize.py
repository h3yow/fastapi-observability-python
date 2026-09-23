"""Sensitive-data masking and normalization.

Used both for structured log payloads and for any user-supplied content
echoed back in error responses.

Rules
-----
* A *field* is sensitive when its key, normalized to lower case with every
  non ``[a-z0-9]`` character removed, appears in :data:`SENSITIVE_KEYS`.
  Thus ``password``, ``apiKey``, ``api-key`` and ``api_key`` are equivalent.
* Sensitive request/response headers are listed in
  :data:`SENSITIVE_HEADERS` (compared case-insensitively).
* Masking is total (``***``): masked values must never remain recoverable
  from logs or error bodies.
* Nested dicts/lists/tuples are walked recursively. Cyclic structures and
  overly deep structures are defended against so masking itself cannot
  blow up request handling.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

MASK = "***"

#: normalized key (lower-case, [^a-z0-9] removed) -> always masked
SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        # credentials / tokens
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "accesstoken",
        "refreshtoken",
        "authorization",
        "apikey",
        "credential",
        "credentials",
        "privatekey",
        # personal sensitive information
        "idcard",
        "idcardno",
        "passport",
        "ssn",
        "creditcard",
        "cardno",
        "cvv",
        "phone",
        "mobile",
        "email",
        "emailaddress",
        "address",
    }
)

#: normalized credential key suffixes; catches variants like
#: ``x-auth-token`` -> ``xauthtoken`` or ``db_password`` -> ``dbpassword``
SENSITIVE_SUFFIXES: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "apikey",
        "credential",
        "privatekey",
    }
)

#: header names, lower-cased, whose values are credentials
SENSITIVE_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
    }
)

#: ``Bearer <token>`` / basic credentials embedded in free text
_EMBEDDED_CREDENTIAL_RE = re.compile(
    r"(?i)(bearer|basic)\s+[A-Za-z0-9\-\._~+/]+=*"
)

_MAX_DEPTH = 8


def normalize_key(key: Any) -> str:
    """Lower-case *key* and strip everything but ``[a-z0-9]``."""
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def is_sensitive_key(key: Any) -> bool:
    """Whether *key* denotes a sensitive field.

    Credential keys match either the exact normalized set or a controlled
    set of suffixes (so ``x-auth-token`` / ``db_password`` are covered);
    personal-information keys match exactly only.
    """
    normalized = normalize_key(key)
    if normalized in SENSITIVE_KEYS:
        return True
    return any(normalized.endswith(suffix) for suffix in SENSITIVE_SUFFIXES)


def mask_value(value: Any) -> str:
    """Return an opaque replacement for a sensitive value."""
    return MASK


def sanitize(obj: Any, *, _depth: int = 0, _seen: set[int] | None = None) -> Any:
    """Return a copy of *obj* with sensitive data replaced by :data:`MASK`.

    The result only contains JSON-friendly primitives, dicts and lists.
    """
    if _seen is None:
        _seen = set()

    if _depth > _MAX_DEPTH:
        return MASK

    if obj is None or isinstance(obj, (bool, int, float)):
        return obj

    if isinstance(obj, str):
        return _EMBEDDED_CREDENTIAL_RE.sub(r"\1 " + MASK, obj)

    if isinstance(obj, bytes):
        return MASK

    if isinstance(obj, Mapping):
        obj_id = id(obj)
        if obj_id in _seen:
            return MASK
        _seen.add(obj_id)
        try:
            return {
                str(k): (
                    mask_value(v)
                    if is_sensitive_key(k)
                    else sanitize(v, _depth=_depth + 1, _seen=_seen)
                )
                for k, v in obj.items()
            }
        finally:
            _seen.discard(obj_id)

    if isinstance(obj, (list, tuple, set, frozenset)):
        obj_id = id(obj)
        if obj_id in _seen:
            return MASK
        _seen.add(obj_id)
        try:
            return [
                sanitize(v, _depth=_depth + 1, _seen=_seen) for v in obj
            ]
        finally:
            _seen.discard(obj_id)

    # unknown types: only keep their str form, then redact credentials
    return _EMBEDDED_CREDENTIAL_RE.sub(r"\1 " + MASK, str(obj))


def sanitize_headers(headers: Any) -> dict[str, str]:
    """Return a header mapping safe for logging.

    *headers* may be a ``starlette.datastructures.Headers`` or any mapping.
    """
    items = getattr(headers, "items", None)
    if items is None:
        return {}
    result: dict[str, str] = {}
    for key, value in items():
        lower = key.lower()
        result[lower] = MASK if lower in SENSITIVE_HEADERS else str(value)
    return result


def sanitize_validation_errors(detail: Any) -> Any:
    """Sanitize a pydantic-style validation error list.

    Generic key-based masking does not suffice here: pydantic echoes the
    offending value under the innocent key ``input`` (and sometimes inside
    ``ctx``), while the sensitive field name only appears as a *value* of
    ``loc``. So when any element of ``loc`` denotes a sensitive field, the
    echoed ``input``/``ctx`` of that error are masked.
    """
    if not isinstance(detail, list):
        return sanitize(detail)
    result: list[Any] = []
    for err in detail:
        if not isinstance(err, Mapping):
            result.append(sanitize(err))
            continue
        loc = err.get("loc")
        touches_sensitive = isinstance(loc, (list, tuple)) and any(
            is_sensitive_key(part) for part in loc
        )
        if touches_sensitive:
            err = {
                k: (MASK if k in ("input", "ctx") else v)
                for k, v in err.items()
            }
        result.append(sanitize(err))
    return result
