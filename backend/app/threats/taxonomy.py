"""Threat Analytics taxonomy for deterministic correlation output."""

from enum import StrEnum


class ThreatInsightType(StrEnum):
    """Supported lightweight threat insight types."""

    REPEATED_AUTH_FAILURE = "repeated_auth_failure"
    SUSPICIOUS_IP_REUSE = "suspicious_ip_reuse"
    IOC_MATCH = "ioc_match"
    ENDPOINT_REPETITION = "endpoint_repetition"
    EVENT_BURST = "event_burst"


class IndicatorType(StrEnum):
    """Supported IOC indicator classes."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


class RiskLevel(StrEnum):
    """Human-readable risk bands derived from deterministic scores."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

