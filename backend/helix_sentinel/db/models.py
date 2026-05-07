"""Model import registry for Alembic metadata discovery."""

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
    "AnalyticsPipeline",
    "AuditEvent",
    "Base",
    "DetectionRule",
    "DetectionTestCase",
    "Indicator",
    "Permission",
    "Role",
    "RoleAssignment",
    "SecurityEvent",
    "User",
    "ValidationRun",
]

