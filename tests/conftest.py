"""Shared fixtures and assertion helpers.

Tests print a structured line per assertion containing the *input*, the
*request_id* under judgment and the *basis* of the judgment, so a failure
(or a log review) always shows distinguishable reasoning.
"""
from __future__ import annotations

import json
import logging
import sys
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.metrics import registry
from app.routes import background_observations


def check(condition: bool, basis: str, *, input: object = None,
          request_id: object = None, actual: object = None) -> None:
    """Assert *condition* and always print the judgment context.

    *basis* states the rule the check relies on; input / request_id /
    actual are printed verbatim so every assertion is distinguishable.
    """
    record = {
        "test_log": True,
        "input": input,
        "request_id": request_id,
        "actual": actual,
        "basis": basis,
        "verdict": "PASS" if condition else "FAIL",
    }
    print("\nTEST_ASSERT " + json.dumps(record, ensure_ascii=False, default=str),
          file=sys.stderr, flush=True)
    assert condition, (
        f"{basis} | input={input!r} request_id={request_id!r} actual={actual!r}"
    )


class _ListHandler(logging.Handler):
    """Collects JSON-formatted log lines emitted during a test."""

    def __init__(self) -> None:
        super().__init__()
        from app.logging_setup import JsonFormatter

        self.setFormatter(JsonFormatter())
        self.records: list[dict] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.records.append(json.loads(self.format(record)))
        except Exception:  # pragma: no cover - formatting must not break tests
            pass

    def lines_for(self, request_id: str) -> list[dict]:
        return [r for r in self.records if r.get("request_id") == request_id]


@pytest.fixture
def log_capture() -> Iterator[_ListHandler]:
    handler = _ListHandler()
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        yield handler
    finally:
        root.removeHandler(handler)


@pytest.fixture(autouse=True)
def _reset_state() -> Iterator[None]:
    registry.reset()
    background_observations.clear()
    yield
    registry.reset()
    background_observations.clear()


@pytest.fixture
def client() -> Iterator[TestClient]:
    from main import app

    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
