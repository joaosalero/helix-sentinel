"""Detection rule lifecycle and metadata taxonomy."""

from enum import StrEnum


class DetectionSeverity(StrEnum):
    """Normalized detection severity values."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionStatus(StrEnum):
    """Operational lifecycle states for detection rules."""

    DRAFT = "draft"
    ACTIVE = "active"
    DEPRECATED = "deprecated"


class DetectionRuleType(StrEnum):
    """Supported detection rule source formats."""

    SIGMA = "sigma"


class DetectionCategory(StrEnum):
    """Pragmatic detection categories for filtering and reporting."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    CLOUD = "cloud"
    IOC = "ioc"
    AUDIT = "audit"
    GENERIC = "generic"

