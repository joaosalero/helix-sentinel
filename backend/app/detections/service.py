"""Detection Engineering application service."""

import logging
from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.audit.events import AuditAction
from app.audit.service import AuditService
from app.detections.metrics import detection_rule_imports_total
from app.detections.parser import SigmaParser
from app.detections.repositories import DetectionRuleRepository
from app.detections.schemas import (
    DetectionRule,
    DetectionRuleListFilters,
    DetectionRuleListResponse,
    DetectionRuleSummary,
    SigmaRuleImportRequest,
)

logger = logging.getLogger(__name__)


class DetectionRuleService:
    """Manage detection rule ingestion and retrieval."""

    def __init__(
        self,
        repository: DetectionRuleRepository,
        parser: SigmaParser,
        audit: AuditService,
    ) -> None:
        self.repository = repository
        self.parser = parser
        self.audit = audit

    async def import_sigma(
        self,
        request: SigmaRuleImportRequest,
        *,
        correlation_id: str | None,
    ) -> DetectionRule:
        """Parse and persist a Sigma rule without executing detection logic."""
        parsed = self.parser.parse(request.content)
        now = datetime.now(UTC)
        metadata = parsed.metadata.model_copy(
            update={"operational_notes": request.operational_notes}
        )
        rule = DetectionRule(
            id=uuid4(),
            title=parsed.title,
            description=parsed.description,
            status=request.status,
            severity=parsed.severity,
            category=parsed.category,
            source=parsed.source,
            sigma_id=parsed.sigma_id,
            sigma_status=parsed.sigma_status,
            raw_rule=parsed.raw_rule,
            detection=parsed.detection,
            metadata=metadata,
            attack=parsed.attack,
            created_at=now,
            updated_at=now,
        )
        saved = await self.repository.create(rule)
        detection_rule_imports_total.labels(
            status=saved.status.value,
            severity=saved.severity.value,
        ).inc()
        await self.audit.record(
            AuditAction.DETECTION_RULE_IMPORTED,
            "success",
            correlation_id=correlation_id,
            resource=str(saved.id),
            metadata={
                "severity": saved.severity.value,
                "category": saved.category.value,
                "attack_techniques": [technique.technique_id for technique in saved.attack],
            },
        )
        logger.info(
            "Detection rule imported",
            extra={
                "correlation_id": correlation_id,
                "rule_id": str(saved.id),
                "severity": saved.severity.value,
            },
        )
        return saved

    async def get(self, rule_id: UUID) -> DetectionRule | None:
        """Return a detection rule by ID."""
        return await self.repository.get(rule_id)

    async def list(self, filters: DetectionRuleListFilters) -> DetectionRuleListResponse:
        """Return a filtered and paginated rule list."""
        rules, total = await self.repository.list(filters)
        return DetectionRuleListResponse(
            items=[_summary(rule) for rule in rules],
            total=total,
            limit=filters.limit,
            offset=filters.offset,
        )


def _summary(rule: DetectionRule) -> DetectionRuleSummary:
    return DetectionRuleSummary(
        id=rule.id,
        title=rule.title,
        status=rule.status,
        severity=rule.severity,
        category=rule.category,
        tags=rule.metadata.tags,
        attack_techniques=[technique.technique_id for technique in rule.attack],
        updated_at=rule.updated_at,
    )

