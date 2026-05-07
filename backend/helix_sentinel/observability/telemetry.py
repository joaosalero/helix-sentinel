"""OpenTelemetry integration hooks."""

from fastapi import FastAPI
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from helix_sentinel.core.config import Settings


def configure_tracing(app: FastAPI, settings: Settings) -> None:
    """Configure tracing when enabled by environment.

    Exporters are deliberately not hard-coded so local, staging, and production
    environments can select collectors without application refactoring.
    """
    if settings.otel_enabled:
        FastAPIInstrumentor.instrument_app(app)

