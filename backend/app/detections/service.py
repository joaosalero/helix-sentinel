"""Detection Engineering application service."""

from __future__ import annotations

import builtins
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from app.audit.events import AuditAction
from app.audit.service import AuditService
from app.detections.metrics import (
    detection_alerts_created_total,
    detection_rule_executions_total,
    detection_rule_imports_total,
)
from app.detections.parser import SigmaParser
from app.detections.repositories import DetectionAlertRepository, DetectionRuleRepository
from app.detections.schemas import (
    DetectionAlert,
    DetectionAlertStatus,
    DetectionExecutionMatch,
    DetectionExecutionRequest,
    DetectionExecutionResponse,
    DetectionRule,
    DetectionRuleListFilters,
    DetectionRuleListResponse,
    DetectionRuleSummary,
    SigmaRuleImportRequest,
)
from app.detections.taxonomy import DetectionStatus
from app.events.repositories import EventRepository, NormalizedEventQuery
from app.events.schemas import NormalizedEvent
from app.events.taxonomy import EventCategory

logger = logging.getLogger(__name__)


class DetectionRuleService:
    """Manage detection rule ingestion and retrieval."""

    def __init__(
        self,
        repository: DetectionRuleRepository,
        parser: SigmaParser,
        audit: AuditService,
        event_repository: EventRepository | None = None,
        alert_repository: DetectionAlertRepository | None = None,
    ) -> None:
        self.repository = repository
        self.parser = parser
        self.audit = audit
        self.event_repository = event_repository
        self.alert_repository = alert_repository

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

    async def execute(
        self,
        rule_id: UUID,
        request: DetectionExecutionRequest,
        *,
        actor_id: UUID | None,
        actor_email: str | None,
        correlation_id: str | None,
    ) -> DetectionExecutionResponse | None:
        """Evaluate one active rule against bounded normalized event history."""
        rule = await self.repository.get(rule_id)
        if rule is None:
            return None
        if self.event_repository is None:
            msg = "Detection execution requires an event repository"
            raise RuntimeError(msg)

        events = await self.event_repository.list_normalized_events(
            NormalizedEventQuery(
                start_time=request.start_time,
                end_time=request.end_time,
                tenant_id=request.tenant_id,
                source=request.source,
                category=_event_category_for_rule(rule),
                limit=request.limit,
            )
        )
        matches = _evaluate_rule(rule, events)
        executed_at = datetime.now(UTC)
        created_alerts = await self._persist_alerts(
            rule,
            matches,
            executed_at=executed_at,
            correlation_id=correlation_id,
        )
        response = DetectionExecutionResponse(
            rule_id=rule.id,
            rule_title=rule.title,
            rule_status=rule.status,
            evaluated_events=len(events),
            matched_events=len(matches),
            matches=matches,
            executed_at=executed_at,
        )
        detection_rule_executions_total.labels(
            rule_status=rule.status.value,
            matched=str(bool(matches)).lower(),
        ).inc()
        await self.audit.record(
            AuditAction.DETECTION_RULE_EXECUTED,
            "success" if rule.status == DetectionStatus.ACTIVE else "failure",
            actor_id=actor_id,
            actor_email=actor_email,
            resource=str(rule.id),
            correlation_id=correlation_id,
            metadata={
                "rule_status": rule.status.value,
                "evaluated_events": len(events),
                "matched_events": len(matches),
                "created_alerts": created_alerts,
                "tenant_id": request.tenant_id,
            },
        )
        logger.info(
            "Detection rule execution completed",
            extra={
                "correlation_id": correlation_id,
                "rule_id": str(rule.id),
                "rule_status": rule.status.value,
                "evaluated_events": len(events),
                "matched_events": len(matches),
                "created_alerts": created_alerts,
            },
        )
        return response

    async def _persist_alerts(
        self,
        rule: DetectionRule,
        matches: builtins.list[DetectionExecutionMatch],
        *,
        executed_at: datetime,
        correlation_id: str | None,
    ) -> int:
        if self.alert_repository is None or not matches:
            return 0
        alerts = [
            DetectionAlert(
                tenant_id=match.tenant_id,
                rule_id=rule.id,
                event_id=match.event_id,
                severity=rule.severity,
                category=rule.category,
                title=rule.title,
                source_name=match.source_name,
                event_time=match.event_time,
                matched_selections=match.matched_selections,
                correlation_id=correlation_id,
                created_at=executed_at,
                updated_at=executed_at,
            )
            for match in matches
        ]
        created = await self.alert_repository.create_many(alerts)
        if created:
            detection_alerts_created_total.labels(
                severity=rule.severity.value,
                status=DetectionAlertStatus.OPEN.value,
            ).inc(created)
        return created


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


def _evaluate_rule(
    rule: DetectionRule,
    events: list[NormalizedEvent],
) -> list[DetectionExecutionMatch]:
    if rule.status != DetectionStatus.ACTIVE:
        return []
    selectors = _selector_names(rule.detection)
    condition = rule.detection.get("condition")
    matches: list[DetectionExecutionMatch] = []
    for event in events:
        matched = [
            name
            for name in selectors
            if _selector_matches(rule.detection.get(name), event)
        ]
        if _condition_satisfied(condition, selectors, matched):
            matches.append(
                DetectionExecutionMatch(
                    event_id=event.id,
                    tenant_id=event.tenant_id,
                    source_name=event.source_name,
                    event_time=event.event_time,
                    severity=event.severity.value,
                    category=event.category.value,
                    title=event.title,
                    matched_selections=matched,
                )
            )
    return matches


def _selector_names(detection: dict[str, Any]) -> list[str]:
    condition = detection.get("condition")
    candidates = [
        name
        for name, value in detection.items()
        if name != "condition" and isinstance(value, dict)
    ]
    if not isinstance(condition, str):
        return candidates
    referenced = [name for name in candidates if name in condition]
    return referenced or candidates


def _condition_satisfied(
    condition: object,
    selectors: list[str],
    matched: list[str],
) -> bool:
    if not matched:
        return False
    if not isinstance(condition, str):
        return bool(matched)
    normalized = condition.lower()
    matched_names = set(matched)
    if " and " in normalized and " or " not in normalized:
        return set(selectors).issubset(matched_names)
    if " or " in normalized:
        return any(name in matched_names for name in selectors)
    return any(name in matched_names for name in selectors)


def _selector_matches(selector: object, event: NormalizedEvent) -> bool:
    if not isinstance(selector, dict) or not selector:
        return False
    values = _event_values(event)
    for expression, expected in selector.items():
        if not isinstance(expression, str):
            return False
        field, operator = _parse_expression(expression)
        observed = values.get(field, [])
        if not _value_matches(observed, operator, expected):
            return False
    return True


def _parse_expression(expression: str) -> tuple[str, str]:
    field, _, modifier = expression.partition("|")
    operator = modifier.lower() if modifier else "equals"
    return field.strip().lower(), operator


def _value_matches(observed: list[str], operator: str, expected: object) -> bool:
    expected_values = expected if isinstance(expected, list) else [expected]
    normalized_expected = [str(value).lower() for value in expected_values if value is not None]
    normalized_observed = [value.lower() for value in observed]
    for actual in normalized_observed:
        for candidate in normalized_expected:
            if operator == "contains" and candidate in actual:
                return True
            if operator == "endswith" and actual.endswith(candidate):
                return True
            if operator == "startswith" and actual.startswith(candidate):
                return True
            if operator == "equals" and actual == candidate:
                return True
    return False


def _event_values(event: NormalizedEvent) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {
        "title": [event.title],
        "source": [event.source_name],
        "source_name": [event.source_name],
        "category": [event.category.value],
        "severity": [event.severity.value],
    }
    _add_value(values, "source_product", event.source_product)
    _add_value(values, "source_vendor", event.source_vendor)
    for prefix, model in (("actor", event.actor), ("asset", event.asset)):
        for key, value in model.model_dump(exclude_none=True).items():
            _add_value(values, f"{prefix}.{key}", value)
            _add_value(values, key, value)
    for prefix, mapping in (
        ("network", event.network),
        ("ioc", event.ioc),
        ("enrichment", event.enrichment),
    ):
        for key, value in mapping.items():
            _add_value(values, f"{prefix}.{key}", value)
            _add_value(values, key, value)
    return values


def _add_value(values: dict[str, list[str]], key: str, value: object) -> None:
    if isinstance(value, str) and value:
        values.setdefault(key.lower(), []).append(value)


def _event_category_for_rule(rule: DetectionRule) -> EventCategory | None:
    try:
        return EventCategory(rule.category.value)
    except ValueError:
        return None
