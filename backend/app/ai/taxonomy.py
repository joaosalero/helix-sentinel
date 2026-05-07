"""AI-assisted analytics taxonomy."""

from enum import StrEnum


class AnomalyType(StrEnum):
    """Supported deterministic anomaly categories."""

    FREQUENCY = "frequency"
    SEVERITY = "severity"
    EVENT_BURST = "event_burst"
    SUSPICIOUS_CLASSIFICATION = "suspicious_classification"


class ClassificationLabel(StrEnum):
    """Lightweight classification labels for event enrichment."""

    SUSPICIOUS_URL = "suspicious_url"
    SUSPICIOUS_EMAIL = "suspicious_email"
    SUSPICIOUS_PROCESS = "suspicious_process"
    IOC_RELATED = "ioc_related"
    BENIGN_OR_UNKNOWN = "benign_or_unknown"


class ConfidenceLevel(StrEnum):
    """Confidence bands derived from transparent scoring factors."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

