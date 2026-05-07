"""Detection rule repository contracts and in-memory implementation."""

from dataclasses import dataclass, field
from uuid import UUID

from app.detections.schemas import DetectionRule, DetectionRuleListFilters


class DetectionRuleRepository:
    """Persistence boundary for detection rule management."""

    async def create(self, rule: DetectionRule) -> DetectionRule:
        """Persist a detection rule."""
        raise NotImplementedError

    async def get(self, rule_id: UUID) -> DetectionRule | None:
        """Return a detection rule by ID."""
        raise NotImplementedError

    async def list(self, filters: DetectionRuleListFilters) -> tuple[list[DetectionRule], int]:
        """Return filtered and paginated detection rules."""
        raise NotImplementedError


@dataclass
class InMemoryDetectionRuleRepository(DetectionRuleRepository):
    """Local/test repository for detection rule workflows."""

    rules: list[DetectionRule] = field(default_factory=list)

    async def create(self, rule: DetectionRule) -> DetectionRule:
        self.rules.append(rule)
        return rule

    async def get(self, rule_id: UUID) -> DetectionRule | None:
        return next((rule for rule in self.rules if rule.id == rule_id), None)

    async def list(self, filters: DetectionRuleListFilters) -> tuple[list[DetectionRule], int]:
        filtered = [
            rule
            for rule in self.rules
            if (filters.status is None or rule.status == filters.status)
            and (filters.severity is None or rule.severity == filters.severity)
            and (filters.category is None or rule.category == filters.category)
            and (filters.tag is None or filters.tag in rule.metadata.tags)
            and (
                filters.attack_technique is None
                or filters.attack_technique in {technique.technique_id for technique in rule.attack}
            )
        ]
        filtered.sort(key=lambda rule: rule.updated_at, reverse=True)
        return filtered[filters.offset : filters.offset + filters.limit], len(filtered)

