"""Structured logging configuration for application and audit telemetry."""

import logging
import sys

from pythonjsonlogger.json import JsonFormatter

from helix_sentinel.core.config import Settings


def configure_logging(settings: Settings) -> None:
    """Configure JSON logs suitable for collection by observability tooling."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s %(correlation_id)s")
    )

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.log_level.upper())

