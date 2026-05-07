"""IOC enrichment taxonomy."""

from enum import StrEnum


class IndicatorType(StrEnum):
    """Supported indicator classes."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


class IOCSeverity(StrEnum):
    """Operational IOC severity values."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceReliability(StrEnum):
    """Source reliability levels used for confidence scoring."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERIFIED = "verified"


class EnrichmentStatus(StrEnum):
    """Status values for event-to-IOC enrichment."""

    MATCHED = "matched"
    NO_MATCH = "no_match"
    SKIPPED = "skipped"

