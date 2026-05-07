"""Pragmatic event taxonomy used by ingestion and analytics foundations."""

from enum import StrEnum


class EventCategory(StrEnum):
    """High-level categories intentionally kept small for maintainability."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    IOC = "ioc"
    AUDIT = "audit"
    SYSTEM = "system"
    GENERIC = "generic"


class EventSeverity(StrEnum):
    """Normalized severity scale for query-friendly analytics."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SUPPORTED_CATEGORIES = frozenset(category.value for category in EventCategory)
SUPPORTED_SEVERITIES = frozenset(severity.value for severity in EventSeverity)

