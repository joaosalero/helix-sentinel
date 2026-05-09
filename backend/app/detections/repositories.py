"""Detection rule repository contracts and in-memory implementation."""

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import Select, case, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from app.detections.models import (
    DetectionAlertRecord,
    DetectionAttackMappingRecord,
    DetectionRuleRecord,
)
from app.detections.schemas import (
    AttackTechnique,
    DetectionAlert,
    DetectionAlertListFilters,
    DetectionAlertStatus,
    DetectionRule,
    DetectionRuleListFilters,
    DetectionRuleMetadata,
)


@dataclass(frozen=True)
class AlertReportingSnapshot:
    """Aggregated alert workflow metrics for SOC reporting."""

    total_alerts: int = 0
    open_alerts: int = 0
    acknowledged_alerts: int = 0
    closed_alerts: int = 0
    high_or_critical_alerts: int = 0
    unassigned_open_alerts: int = 0
    oldest_open_alert_minutes: float | None = None
    mtta_minutes: float | None = None
    mttr_minutes: float | None = None
    true_positive_alerts: int = 0
    false_positive_alerts: int = 0


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
            and (filters.source is None or rule.source == filters.source)
            and _contains_text(rule.title, filters.title)
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
            base_statement = _filtered_statement(filters)
            records = list(
                (
                    await session.scalars(
                        base_statement.order_by(DetectionRuleRecord.updated_at.desc())
                        .offset(filters.offset)
                        .limit(filters.limit)
                    )
                ).all()
            )
            total = await session.scalar(
                select(func.count()).select_from(
                    _filtered_statement(filters, load_attack=False).subquery()
                )
            )
            return [_to_rule_schema(record) for record in records], int(total or 0)


class DetectionAlertRepository:
    """Persistence boundary for detection alert lifecycle records."""

    async def create_many(self, alerts: list[DetectionAlert]) -> int:
        """Persist new alerts and return the number of created records."""
        raise NotImplementedError

    async def get(self, alert_id: UUID, tenant_id: str) -> DetectionAlert | None:
        """Return one alert within a tenant boundary."""
        raise NotImplementedError

    async def list(self, filters: DetectionAlertListFilters) -> tuple[list[DetectionAlert], int]:
        """Return tenant-scoped alerts for analyst queues."""
        raise NotImplementedError

    async def reporting_snapshot(
        self,
        *,
        tenant_id: str | None,
        start_time: datetime,
        end_time: datetime,
        now: datetime,
    ) -> AlertReportingSnapshot:
        """Return bounded alert workflow aggregates for SOC reporting."""
        raise NotImplementedError

    async def update_workflow(
        self,
        alert_id: UUID,
        tenant_id: str,
        *,
        status: DetectionAlertStatus,
        assigned_to: UUID | None,
        acknowledged_at: datetime | None,
        closed_at: datetime | None,
        disposition: str | None,
        investigation_note: str | None,
        updated_at: datetime,
    ) -> DetectionAlert | None:
        """Persist an analyst investigation state transition."""
        raise NotImplementedError


@dataclass
class InMemoryDetectionAlertRepository(DetectionAlertRepository):
    """Local/test repository for detection alert lifecycle state."""

    alerts: list[DetectionAlert] = field(default_factory=list)

    async def create_many(self, alerts: list[DetectionAlert]) -> int:
        existing = {(alert.rule_id, alert.event_id) for alert in self.alerts}
        created: list[DetectionAlert] = []
        for alert in alerts:
            key = (alert.rule_id, alert.event_id)
            if key in existing:
                continue
            created.append(alert)
            existing.add(key)
        self.alerts.extend(created)
        return len(created)

    async def get(self, alert_id: UUID, tenant_id: str) -> DetectionAlert | None:
        return next(
            (
                alert
                for alert in self.alerts
                if alert.id == alert_id and alert.tenant_id == tenant_id
            ),
            None,
        )

    async def list(self, filters: DetectionAlertListFilters) -> tuple[list[DetectionAlert], int]:
        filtered = [
            alert
            for alert in self.alerts
            if (filters.tenant_id is None or alert.tenant_id == filters.tenant_id)
            and (filters.status is None or alert.status == filters.status)
            and (filters.severity is None or alert.severity == filters.severity)
            and (filters.category is None or alert.category == filters.category)
            and (filters.source is None or alert.source_name == filters.source)
            and (filters.rule_id is None or alert.rule_id == filters.rule_id)
            and (filters.event_id is None or alert.event_id == filters.event_id)
            and (filters.assigned_to is None or alert.assigned_to == filters.assigned_to)
            and (filters.start_time is None or alert.event_time >= filters.start_time)
            and (filters.end_time is None or alert.event_time <= filters.end_time)
        ]
        filtered.sort(key=lambda alert: alert.updated_at, reverse=True)
        return filtered[filters.offset : filters.offset + filters.limit], len(filtered)

    async def reporting_snapshot(
        self,
        *,
        tenant_id: str | None,
        start_time: datetime,
        end_time: datetime,
        now: datetime,
    ) -> AlertReportingSnapshot:
        alerts = [
            alert
            for alert in self.alerts
            if start_time <= alert.event_time <= end_time
            and (tenant_id is None or alert.tenant_id == tenant_id)
        ]
        open_alerts = [alert for alert in alerts if alert.status == DetectionAlertStatus.OPEN]
        acknowledged = [
            _minutes_between(alert.created_at, alert.acknowledged_at)
            for alert in alerts
            if alert.acknowledged_at is not None
        ]
        closed = [
            _minutes_between(alert.created_at, alert.closed_at)
            for alert in alerts
            if alert.closed_at is not None
        ]
        return AlertReportingSnapshot(
            total_alerts=len(alerts),
            open_alerts=sum(alert.status == DetectionAlertStatus.OPEN for alert in alerts),
            acknowledged_alerts=sum(
                alert.status == DetectionAlertStatus.ACKNOWLEDGED for alert in alerts
            ),
            closed_alerts=sum(alert.status == DetectionAlertStatus.CLOSED for alert in alerts),
            high_or_critical_alerts=sum(
                alert.severity.value in {"high", "critical"} for alert in alerts
            ),
            unassigned_open_alerts=sum(alert.assigned_to is None for alert in open_alerts),
            oldest_open_alert_minutes=(
                max(_minutes_between(alert.created_at, now) for alert in open_alerts)
                if open_alerts
                else None
            ),
            mtta_minutes=_average(acknowledged),
            mttr_minutes=_average(closed),
            true_positive_alerts=sum(
                alert.disposition == "true_positive" for alert in alerts
            ),
            false_positive_alerts=sum(
                alert.disposition == "false_positive" for alert in alerts
            ),
        )

    async def update_workflow(
        self,
        alert_id: UUID,
        tenant_id: str,
        *,
        status: DetectionAlertStatus,
        assigned_to: UUID | None,
        acknowledged_at: datetime | None,
        closed_at: datetime | None,
        disposition: str | None,
        investigation_note: str | None,
        updated_at: datetime,
    ) -> DetectionAlert | None:
        alert = await self.get(alert_id, tenant_id)
        if alert is None:
            return None
        updated = alert.model_copy(
            update={
                "status": status,
                "assigned_to": assigned_to,
                "acknowledged_at": acknowledged_at,
                "closed_at": closed_at,
                "disposition": disposition,
                "investigation_note": investigation_note,
                "updated_at": updated_at,
            }
        )
        self.alerts = [updated if current.id == alert_id else current for current in self.alerts]
        return updated


class PostgresDetectionAlertRepository(DetectionAlertRepository):
    """PostgreSQL-backed detection alert lifecycle repository."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def create_many(self, alerts: list[DetectionAlert]) -> int:
        if not alerts:
            return 0
        values = [_to_alert_record_values(alert) for alert in alerts]
        statement = (
            insert(DetectionAlertRecord)
            .values(values)
            .on_conflict_do_nothing(constraint="uq_detection_alerts_rule_event")
            .returning(DetectionAlertRecord.id)
        )
        async with self.session_factory() as session, session.begin():
            result = await session.execute(statement)
            return len(result.scalars().all())

    async def get(self, alert_id: UUID, tenant_id: str) -> DetectionAlert | None:
        async with self.session_factory() as session:
            record = await session.scalar(
                select(DetectionAlertRecord).where(
                    DetectionAlertRecord.id == alert_id,
                    DetectionAlertRecord.tenant_id == tenant_id,
                )
            )
            return _to_alert_schema(record) if record is not None else None

    async def list(self, filters: DetectionAlertListFilters) -> tuple[list[DetectionAlert], int]:
        async with self.session_factory() as session:
            statement = _filtered_alert_statement(filters)
            records = list(
                (
                    await session.scalars(
                        statement.order_by(DetectionAlertRecord.updated_at.desc())
                        .offset(filters.offset)
                        .limit(filters.limit)
                    )
                ).all()
            )
            total = await session.scalar(
                select(func.count()).select_from(_filtered_alert_statement(filters).subquery())
            )
            return [_to_alert_schema(record) for record in records], int(total or 0)

    async def reporting_snapshot(
        self,
        *,
        tenant_id: str | None,
        start_time: datetime,
        end_time: datetime,
        now: datetime,
    ) -> AlertReportingSnapshot:
        clauses = [
            DetectionAlertRecord.event_time >= start_time,
            DetectionAlertRecord.event_time <= end_time,
        ]
        if tenant_id is not None:
            clauses.append(DetectionAlertRecord.tenant_id == tenant_id)
        minutes_to_ack = func.extract(
            "epoch",
            DetectionAlertRecord.acknowledged_at - DetectionAlertRecord.created_at,
        ) / 60
        minutes_to_close = func.extract(
            "epoch",
            DetectionAlertRecord.closed_at - DetectionAlertRecord.created_at,
        ) / 60
        statement = select(
            func.count().label("total_alerts"),
            _count_when(DetectionAlertRecord.status == DetectionAlertStatus.OPEN.value).label(
                "open_alerts"
            ),
            _count_when(
                DetectionAlertRecord.status == DetectionAlertStatus.ACKNOWLEDGED.value
            ).label("acknowledged_alerts"),
            _count_when(DetectionAlertRecord.status == DetectionAlertStatus.CLOSED.value).label(
                "closed_alerts"
            ),
            _count_when(
                DetectionAlertRecord.severity.in_(["high", "critical"])
            ).label("high_or_critical_alerts"),
            _count_when(
                DetectionAlertRecord.status == DetectionAlertStatus.OPEN.value,
                DetectionAlertRecord.assigned_to.is_(None),
            ).label("unassigned_open_alerts"),
            func.min(
                case(
                    (
                        DetectionAlertRecord.status == DetectionAlertStatus.OPEN.value,
                        DetectionAlertRecord.created_at,
                    ),
                    else_=None,
                )
            ).label("oldest_open_created_at"),
            func.avg(
                case(
                    (DetectionAlertRecord.acknowledged_at.is_not(None), minutes_to_ack),
                    else_=None,
                )
            ).label("mtta_minutes"),
            func.avg(
                case(
                    (DetectionAlertRecord.closed_at.is_not(None), minutes_to_close),
                    else_=None,
                )
            ).label("mttr_minutes"),
            _count_when(DetectionAlertRecord.disposition == "true_positive").label(
                "true_positive_alerts"
            ),
            _count_when(DetectionAlertRecord.disposition == "false_positive").label(
                "false_positive_alerts"
            ),
        ).where(*clauses)
        async with self.session_factory() as session:
            row = (await session.execute(statement)).one()
        oldest_open = row.oldest_open_created_at
        return AlertReportingSnapshot(
            total_alerts=int(row.total_alerts or 0),
            open_alerts=int(row.open_alerts or 0),
            acknowledged_alerts=int(row.acknowledged_alerts or 0),
            closed_alerts=int(row.closed_alerts or 0),
            high_or_critical_alerts=int(row.high_or_critical_alerts or 0),
            unassigned_open_alerts=int(row.unassigned_open_alerts or 0),
            oldest_open_alert_minutes=(
                _minutes_between(oldest_open, now) if oldest_open is not None else None
            ),
            mtta_minutes=_rounded_float(row.mtta_minutes),
            mttr_minutes=_rounded_float(row.mttr_minutes),
            true_positive_alerts=int(row.true_positive_alerts or 0),
            false_positive_alerts=int(row.false_positive_alerts or 0),
        )

    async def update_workflow(
        self,
        alert_id: UUID,
        tenant_id: str,
        *,
        status: DetectionAlertStatus,
        assigned_to: UUID | None,
        acknowledged_at: datetime | None,
        closed_at: datetime | None,
        disposition: str | None,
        investigation_note: str | None,
        updated_at: datetime,
    ) -> DetectionAlert | None:
        statement = (
            update(DetectionAlertRecord)
            .where(
                DetectionAlertRecord.id == alert_id,
                DetectionAlertRecord.tenant_id == tenant_id,
            )
            .values(
                status=status.value,
                assigned_to=assigned_to,
                acknowledged_at=acknowledged_at,
                closed_at=closed_at,
                disposition=disposition,
                investigation_note=investigation_note,
                updated_at=updated_at,
            )
            .returning(DetectionAlertRecord)
        )
        async with self.session_factory() as session, session.begin():
            record = await session.scalar(statement)
            return _to_alert_schema(record) if record is not None else None


def _filtered_statement(
    filters: DetectionRuleListFilters,
    *,
    load_attack: bool = True,
) -> Select[tuple[DetectionRuleRecord]]:
    statement = select(DetectionRuleRecord)
    if load_attack:
        statement = statement.options(selectinload(DetectionRuleRecord.attack_mappings))
    if filters.status is not None:
        statement = statement.where(DetectionRuleRecord.status == filters.status.value)
    if filters.severity is not None:
        statement = statement.where(DetectionRuleRecord.severity == filters.severity.value)
    if filters.category is not None:
        statement = statement.where(DetectionRuleRecord.category == filters.category.value)
    if filters.source is not None:
        statement = statement.where(DetectionRuleRecord.source == filters.source)
    if filters.title is not None:
        statement = statement.where(
            DetectionRuleRecord.title.ilike(f"%{_escape_like(filters.title)}%", escape="\\")
        )
    if filters.tag is not None:
        statement = statement.where(DetectionRuleRecord.tags.contains([filters.tag]))
    if filters.attack_technique is not None:
        statement = statement.where(
            DetectionRuleRecord.attack_mappings.any(
                DetectionAttackMappingRecord.technique_id == filters.attack_technique
            )
        )
    return statement


def _filtered_alert_statement(
    filters: DetectionAlertListFilters,
) -> Select[tuple[DetectionAlertRecord]]:
    statement = select(DetectionAlertRecord)
    if filters.tenant_id is not None:
        statement = statement.where(DetectionAlertRecord.tenant_id == filters.tenant_id)
    if filters.status is not None:
        statement = statement.where(DetectionAlertRecord.status == filters.status.value)
    if filters.severity is not None:
        statement = statement.where(DetectionAlertRecord.severity == filters.severity.value)
    if filters.category is not None:
        statement = statement.where(DetectionAlertRecord.category == filters.category.value)
    if filters.source is not None:
        statement = statement.where(DetectionAlertRecord.source_name == filters.source)
    if filters.rule_id is not None:
        statement = statement.where(DetectionAlertRecord.rule_id == filters.rule_id)
    if filters.event_id is not None:
        statement = statement.where(DetectionAlertRecord.event_id == filters.event_id)
    if filters.assigned_to is not None:
        statement = statement.where(DetectionAlertRecord.assigned_to == filters.assigned_to)
    if filters.start_time is not None:
        statement = statement.where(DetectionAlertRecord.event_time >= filters.start_time)
    if filters.end_time is not None:
        statement = statement.where(DetectionAlertRecord.event_time <= filters.end_time)
    return statement


def _count_when(*conditions: Any) -> Any:
    condition = conditions[0]
    for next_condition in conditions[1:]:
        condition = condition & next_condition
    return func.sum(case((condition, 1), else_=0))


def _minutes_between(start: datetime, end: datetime | None) -> float:
    if end is None:
        return 0.0
    return round((end - start).total_seconds() / 60, 2)


def _average(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 2) if values else None


def _rounded_float(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, int | float | Decimal | str):
        return round(float(value), 2)
    raise TypeError(f"Unsupported numeric aggregate value: {type(value).__name__}")


def _contains_text(value: str | None, expected: str | None) -> bool:
    if expected is None:
        return True
    return value is not None and expected.lower() in value.lower()


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


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


def _to_alert_record_values(alert: DetectionAlert) -> dict[str, object]:
    return {
        "id": alert.id,
        "tenant_id": alert.tenant_id,
        "rule_id": alert.rule_id,
        "event_id": alert.event_id,
        "status": alert.status.value,
        "severity": alert.severity.value,
        "category": alert.category.value,
        "title": alert.title,
        "source_name": alert.source_name,
        "event_time": alert.event_time,
        "matched_selections": alert.matched_selections,
        "correlation_id": alert.correlation_id,
        "assigned_to": alert.assigned_to,
        "acknowledged_at": alert.acknowledged_at,
        "closed_at": alert.closed_at,
        "disposition": alert.disposition,
        "investigation_note": alert.investigation_note,
        "created_at": alert.created_at,
        "updated_at": alert.updated_at,
    }


def _to_alert_schema(record: DetectionAlertRecord) -> DetectionAlert:
    return DetectionAlert.model_validate(
        {
            "id": record.id,
            "tenant_id": record.tenant_id,
            "rule_id": record.rule_id,
            "event_id": record.event_id,
            "status": record.status,
            "severity": record.severity,
            "category": record.category,
            "title": record.title,
            "source_name": record.source_name,
            "event_time": record.event_time,
            "matched_selections": record.matched_selections,
            "correlation_id": record.correlation_id,
            "assigned_to": record.assigned_to,
            "acknowledged_at": record.acknowledged_at,
            "closed_at": record.closed_at,
            "disposition": record.disposition,
            "investigation_note": record.investigation_note,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }
    )
