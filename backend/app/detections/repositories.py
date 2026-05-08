"""Detection rule repository contracts and in-memory implementation."""

from dataclasses import dataclass, field
from uuid import UUID

from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from app.detections.models import DetectionAttackMappingRecord, DetectionRuleRecord
from app.detections.schemas import (
    AttackTechnique,
    DetectionRule,
    DetectionRuleListFilters,
    DetectionRuleMetadata,
)


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


class PostgresDetectionRuleRepository(DetectionRuleRepository):
    """PostgreSQL-backed detection rule catalog repository."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def create(self, rule: DetectionRule) -> DetectionRule:
        async with self.session_factory() as session, session.begin():
            session.add(_to_rule_record(rule))
        return rule

    async def get(self, rule_id: UUID) -> DetectionRule | None:
        async with self.session_factory() as session:
            record = await session.scalar(
                select(DetectionRuleRecord)
                .options(selectinload(DetectionRuleRecord.attack_mappings))
                .where(DetectionRuleRecord.id == rule_id)
            )
            return _to_rule_schema(record) if record is not None else None

    async def list(self, filters: DetectionRuleListFilters) -> tuple[list[DetectionRule], int]:
        async with self.session_factory() as session:
            statement = _filtered_statement(filters).order_by(DetectionRuleRecord.updated_at.desc())
            records = list((await session.scalars(statement)).all())
            total = len(records)
            window = records[filters.offset : filters.offset + filters.limit]
            return [_to_rule_schema(record) for record in window], total


def _filtered_statement(filters: DetectionRuleListFilters) -> Select[tuple[DetectionRuleRecord]]:
    statement = select(DetectionRuleRecord).options(
        selectinload(DetectionRuleRecord.attack_mappings)
    )
    if filters.status is not None:
        statement = statement.where(DetectionRuleRecord.status == filters.status.value)
    if filters.severity is not None:
        statement = statement.where(DetectionRuleRecord.severity == filters.severity.value)
    if filters.category is not None:
        statement = statement.where(DetectionRuleRecord.category == filters.category.value)
    if filters.tag is not None:
        statement = statement.where(DetectionRuleRecord.tags.contains([filters.tag]))
    if filters.attack_technique is not None:
        statement = statement.where(
            DetectionRuleRecord.attack_mappings.any(
                DetectionAttackMappingRecord.technique_id == filters.attack_technique
            )
        )
    return statement


def _to_rule_record(rule: DetectionRule) -> DetectionRuleRecord:
    return DetectionRuleRecord(
        id=rule.id,
        title=rule.title,
        description=rule.description,
        rule_type=rule.rule_type.value,
        status=rule.status.value,
        severity=rule.severity.value,
        category=rule.category.value,
        source=rule.source,
        sigma_id=rule.sigma_id,
        sigma_status=rule.sigma_status,
        tags=rule.metadata.tags,
        references=rule.metadata.references,
        false_positives=rule.metadata.false_positives,
        author=rule.metadata.author,
        license=rule.metadata.license,
        operational_notes=rule.metadata.operational_notes,
        raw_rule=rule.raw_rule,
        detection=rule.detection,
        tuning_metadata=rule.metadata.tuning_metadata,
        quality_metadata=rule.metadata.quality_metadata,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
        attack_mappings=[
            DetectionAttackMappingRecord(
                technique_id=technique.technique_id,
                technique_name=technique.name,
                tactic=technique.tactic,
            )
            for technique in rule.attack
        ],
    )


def _to_rule_schema(record: DetectionRuleRecord) -> DetectionRule:
    return DetectionRule.model_validate(
        {
            "id": record.id,
            "title": record.title,
            "description": record.description,
            "rule_type": record.rule_type,
            "status": record.status,
            "severity": record.severity,
            "category": record.category,
            "source": record.source,
            "sigma_id": record.sigma_id,
            "sigma_status": record.sigma_status,
            "raw_rule": record.raw_rule,
            "detection": record.detection,
            "metadata": DetectionRuleMetadata(
                tags=record.tags,
                references=record.references,
                false_positives=record.false_positives,
                author=record.author,
                license=record.license,
                operational_notes=record.operational_notes,
                tuning_metadata=record.tuning_metadata,
                quality_metadata=record.quality_metadata,
            ),
            "attack": [
                AttackTechnique(
                    technique_id=mapping.technique_id,
                    name=mapping.technique_name,
                    tactic=mapping.tactic,
                )
                for mapping in record.attack_mappings
            ],
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }
    )
