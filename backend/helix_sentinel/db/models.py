"""Model import registry for Alembic metadata discovery."""

from app.ai.models import AIAnomalyRecord, AIEnrichmentRecord
from app.audit.models import AuditEvent as AuthAuditEvent
from app.detections.models import (
    DetectionAlertRecord,
    DetectionAttackMappingRecord,
    DetectionRuleRecord,
)
from app.enrichment.models import EventIOCMatchRecord, IOCIndicatorRecord
from app.events.models import EventSource, NormalizedSecurityEvent, RawSecurityEvent
from app.threats.models import ThreatInsightRecord, ThreatIOCReferenceRecord
from app.users.models import (
    Permission as AuthPermission,
)
from app.users.models import (
    Role as AuthRole,
)
from app.users.models import (
    RolePermission,
    UserRole,
)
from app.users.models import (
    User as AuthUser,
)
from helix_sentinel.db.base import Base
from helix_sentinel.domains.analytics.models import AIEnrichment, AnalyticsPipeline
from helix_sentinel.domains.audit.models import AuditEvent
from helix_sentinel.domains.detections.models import DetectionRule, DetectionTestCase
from helix_sentinel.domains.events.models import SecurityEvent
from helix_sentinel.domains.identity.models import Permission, Role, RoleAssignment, User
from helix_sentinel.domains.threat_intel.models import Indicator
from helix_sentinel.domains.validation.models import ValidationRun

__all__ = [
    "AIEnrichment",
    "AIEnrichmentRecord",
    "AIAnomalyRecord",
    "AnalyticsPipeline",
    "AuthAuditEvent",
    "AuthPermission",
    "AuthRole",
    "AuthUser",
    "AuditEvent",
    "Base",
    "DetectionAttackMappingRecord",
    "DetectionAlertRecord",
    "DetectionRule",
    "DetectionRuleRecord",
    "DetectionTestCase",
    "EventIOCMatchRecord",
    "EventSource",
    "Indicator",
    "IOCIndicatorRecord",
    "NormalizedSecurityEvent",
    "Permission",
    "RawSecurityEvent",
    "Role",
    "RoleAssignment",
    "RolePermission",
    "SecurityEvent",
    "ThreatIOCReferenceRecord",
    "ThreatInsightRecord",
    "UserRole",
    "User",
    "ValidationRun",
]
