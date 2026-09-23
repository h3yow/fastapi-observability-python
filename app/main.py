"""FastAPI application factory wiring observability pieces together."""
from __future__ import annotations

import logging

from fastapi import FastAPI

from app.logging_setup import configure_logging
from app.middleware import ObservabilityMiddleware
from app.metrics import registry
from app.routes import router


def create_app() -> FastAPI:
    configure_logging(logging.INFO)
    app = FastAPI(title="fastapi-observability-python")
    # added last -> runs outermost, so it sees every response/exception
    app.add_middleware(ObservabilityMiddleware, metrics=registry)
    app.include_router(router)
    return app


app = create_app()
