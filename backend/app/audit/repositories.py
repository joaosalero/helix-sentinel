"""Audit repository protocols and analytics implementations."""

from collections import Counter, defaultdict
from typing import Protocol
from uuid import UUID

from sqlalchemy import case, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.sql import Select
from sqlalchemy.sql.elements import ColumnElement

from app.audit.events import AuditEventCreate
from app.audit.models import AuditEvent
from app.audit.schemas import (
    AuditActionMetric,
    AuditActivityFilter,
    AuditActorMetric,
    AuthenticationActivitySummary,
    AuthorizationActivitySummary,
    InvestigationActivitySummary,
    RecentAuditActivity,
    SecurityActivityFinding,
    SecurityActivitySummary,
)


class AuditRepository(Protocol):
    """Append-only audit event boundary."""

    async def append(self, event: AuditEventCreate) -> None:
        """Persist or emit a sanitized audit event."""


class AuditActivityRepository(Protocol):
    """Audit aggregation query boundary."""

    async def security_activity_summary(
        self,
        filters: AuditActivityFilter,
    ) -> SecurityActivitySummary:
        """Return operational security activity aggregates."""


class InMemoryAuditRepository:
    """Test/local audit repository that retains structured audit events."""

    def __init__(self) -> None:
        self.events: list[AuditEventCreate] = []

    async def append(self, event: AuditEventCreate) -> None:
        self.events.append(event)

    async def security_activity_summary(
        self,
        filters: AuditActivityFilter,
    ) -> SecurityActivitySummary:
        events = _filter_memory_events(self.events, filters)
        action_counts: Counter[tuple[str, str]] = Counter(
            (event.action.value, event.outcome) for event in events
        )
        actor_events: dict[tuple[UUID | None, str | None], list[AuditEventCreate]] = defaultdict(
            list
        )
        for event in events:
            if event.actor_id is not None or event.actor_email_hash is not None:
                actor_events[_actor_key(event)].append(event)
        actions = [
            AuditActionMetric(
                action=action,
                outcome=outcome,
                count=count,
                last_seen=max(
                    event.created_at
                    for event in events
                    if event.action.value == action and event.outcome == outcome
                ),
            )
            for (action, outcome), count in action_counts.most_common(filters.limit)
        ]
        top_actors = [
            AuditActorMetric(
                actor_id=actor_id,
                actor_email_hash=actor_hash,
                count=len(items),
                failure_count=sum(item.outcome == "failure" for item in items),
                last_seen=max(item.created_at for item in items),
            )
            for (actor_id, actor_hash), items in sorted(
                actor_events.items(),
                key=lambda item: (len(item[1]), max(event.created_at for event in item[1])),
                reverse=True,
            )[filters.offset : filters.offset + filters.limit]
        ]
        recent_events = sorted(events, key=lambda event: event.created_at, reverse=True)[
            : filters.limit
        ]
        return _summary_from_counts(
            filters,
            total=len(events),
            action_counts=action_counts,
            active_actor_count=len(actor_events),
            actions=actions,
            top_actors=top_actors,
            recent=[
                RecentAuditActivity(
                    action=event.action.value,
                    outcome=event.outcome,
                    resource=event.resource,
                    correlation_id=event.correlation_id,
                    created_at=event.created_at,
                )
                for event in recent_events
            ],
            investigation_status_counts=_memory_investigation_status_counts(events),
            tenant_scope_denials=sum(_is_tenant_scope_denial(event.metadata) for event in events),
        )


class PostgresAuditRepository:
    """PostgreSQL-backed append-only audit repository."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def append(self, event: AuditEventCreate) -> None:
        async with self.session_factory() as session, session.begin():
            session.add(_to_audit_record(event))

    async def security_activity_summary(
        self,
        filters: AuditActivityFilter,
    ) -> SecurityActivitySummary:
        async with self.session_factory() as session:
            total = int(await session.scalar(_total_statement(filters)) or 0)
            action_counts = await _activity_counts(session, filters)
            active_actor_count = await _active_actor_count(session, filters)
            actions = await _action_metrics(session, filters)
            top_actors = await _actor_metrics(session, filters)
            recent = await _recent_activity(session, filters)
            investigation_status_counts = await _investigation_status_counts(session, filters)
            tenant_scope_denials = int(
                await session.scalar(_tenant_scope_denials_statement(filters)) or 0
            )
        return _summary_from_counts(
            filters,
            total=total,
            action_counts=action_counts,
            active_actor_count=active_actor_count,
            actions=actions,
            top_actors=top_actors,
            recent=recent,
            investigation_status_counts=investigation_status_counts,
            tenant_scope_denials=tenant_scope_denials,
        )


def _to_audit_record(event: AuditEventCreate) -> AuditEvent:
    return AuditEvent(
        action=event.action.value,
        outcome=event.outcome,
        actor_id=event.actor_id,
        actor_email_hash=event.actor_email_hash,
        resource=event.resource,
        correlation_id=event.correlation_id,
        metadata_=event.metadata,
        created_at=event.created_at,
    )


def _filter_memory_events(
    events: list[AuditEventCreate],
    filters: AuditActivityFilter,
) -> list[AuditEventCreate]:
    return [
        event
        for event in events
        if filters.start_time <= event.created_at <= filters.end_time
        and (filters.tenant_id is None or event.metadata.get("tenant_id") == filters.tenant_id)
    ]


def _summary_from_counts(
    filters: AuditActivityFilter,
    *,
    total: int,
    action_counts: Counter[tuple[str, str]],
    active_actor_count: int,
    actions: list[AuditActionMetric],
    top_actors: list[AuditActorMetric],
    recent: list[RecentAuditActivity],
    investigation_status_counts: Counter[str],
    tenant_scope_denials: int,
) -> SecurityActivitySummary:
    successful_auth = action_counts.get(("auth.login_succeeded", "success"), 0)
    failed_auth = action_counts.get(("auth.login_failed", "failure"), 0)
    token_refreshes = action_counts.get(("auth.token_refreshed", "success"), 0)
    logouts = action_counts.get(("auth.logout_requested", "success"), 0)
    user_state_rejections = action_counts.get(("auth.user_state_rejected", "failure"), 0)
    permission_denials = action_counts.get(("auth.permission_denied", "failure"), 0)
    investigation_updates = action_counts.get(("detections.alert_updated", "success"), 0)
    detection_rule_activity = sum(
        count
        for (action, _outcome), count in action_counts.items()
        if action.startswith("detections.rule_")
    )
    event_ingestion_rejections = action_counts.get(("events.validation_failed", "failure"), 0)
    return SecurityActivitySummary(
        period_start=filters.start_time,
        period_end=filters.end_time,
        total_audit_events=total,
        successful_authentications=successful_auth,
        failed_authentications=failed_auth,
        permission_denials=permission_denials,
        tenant_scope_denials=tenant_scope_denials,
        investigation_updates=investigation_updates,
        detection_rule_activity=detection_rule_activity,
        event_ingestion_rejections=event_ingestion_rejections,
        active_actor_count=active_actor_count,
        authentication=AuthenticationActivitySummary(
            successes=successful_auth,
            failures=failed_auth,
            token_refreshes=token_refreshes,
            logouts=logouts,
            user_state_rejections=user_state_rejections,
            failure_ratio=round(failed_auth / (successful_auth + failed_auth), 4)
            if successful_auth + failed_auth
            else 0.0,
        ),
        authorization=AuthorizationActivitySummary(
            permission_denials=permission_denials,
            tenant_scope_denials=tenant_scope_denials,
        ),
        investigations=InvestigationActivitySummary(
            workflow_updates=investigation_updates,
            acknowledgements=investigation_status_counts.get("acknowledged", 0),
            closures=investigation_status_counts.get("closed", 0),
        ),
        actions=actions,
        top_actors=top_actors,
        recent_activity=recent,
        findings=_activity_findings(
            failed_authentications=failed_auth,
            permission_denials=permission_denials,
            tenant_scope_denials=tenant_scope_denials,
            event_ingestion_rejections=event_ingestion_rejections,
            active_actor_count=active_actor_count,
            total=total,
        ),
    )


def _activity_findings(
    *,
    failed_authentications: int,
    permission_denials: int,
    tenant_scope_denials: int,
    event_ingestion_rejections: int,
    active_actor_count: int,
    total: int,
) -> list[SecurityActivityFinding]:
    findings: list[SecurityActivityFinding] = []
    if failed_authentications:
        findings.append(
            SecurityActivityFinding(
                name="authentication_failures",
                severity="high" if failed_authentications >= 10 else "medium",
                count=failed_authentications,
                reason="Failed authentication attempts were recorded in audit activity.",
            )
        )
    if permission_denials:
        findings.append(
            SecurityActivityFinding(
                name="authorization_denials",
                severity="high" if tenant_scope_denials else "medium",
                count=permission_denials,
                reason="Authorization denials indicate blocked access attempts.",
            )
        )
    if event_ingestion_rejections:
        findings.append(
            SecurityActivityFinding(
                name="ingestion_rejections",
                severity="medium",
                count=event_ingestion_rejections,
                reason="Security telemetry was rejected before persistence.",
            )
        )
    if active_actor_count == 0 and total:
        findings.append(
            SecurityActivityFinding(
                name="system_only_audit_activity",
                severity="low",
                count=total,
                reason="Audit activity was recorded without actor attribution in this window.",
            )
        )
    if total == 0:
        findings.append(
            SecurityActivityFinding(
                name="no_audit_activity",
                severity="medium",
                count=0,
                reason="No audit events were observed in the activity window.",
            )
        )
    return findings


def _filter_clauses(filters: AuditActivityFilter) -> tuple[ColumnElement[bool], ...]:
    clauses: list[ColumnElement[bool]] = [
        AuditEvent.created_at >= filters.start_time,
        AuditEvent.created_at <= filters.end_time,
    ]
    if filters.tenant_id is not None:
        clauses.append(AuditEvent.metadata_["tenant_id"].as_string() == filters.tenant_id)
    return tuple(clauses)


def _total_statement(filters: AuditActivityFilter) -> Select[tuple[int]]:
    return select(func.count()).select_from(AuditEvent).where(*_filter_clauses(filters))


async def _activity_counts(
    session: AsyncSession,
    filters: AuditActivityFilter,
) -> Counter[tuple[str, str]]:
    statement = (
        select(AuditEvent.action, AuditEvent.outcome, func.count())
        .where(*_filter_clauses(filters))
        .group_by(AuditEvent.action, AuditEvent.outcome)
    )
    rows = (await session.execute(statement)).all()
    return Counter({(str(action), str(outcome)): int(count) for action, outcome, count in rows})


async def _active_actor_count(
    session: AsyncSession,
    filters: AuditActivityFilter,
) -> int:
    actor_hash = _actor_hash_group_expression()
    grouped_actors = (
        select(AuditEvent.actor_id, actor_hash.label("actor_email_hash"))
        .where(
            *_filter_clauses(filters),
            (AuditEvent.actor_id.is_not(None) | AuditEvent.actor_email_hash.is_not(None)),
        )
        .group_by(AuditEvent.actor_id, actor_hash)
        .subquery()
    )
    statement = select(func.count()).select_from(grouped_actors)
    return int(await session.scalar(statement) or 0)


async def _action_metrics(
    session: AsyncSession,
    filters: AuditActivityFilter,
) -> list[AuditActionMetric]:
    statement = (
        select(
            AuditEvent.action,
            AuditEvent.outcome,
            func.count().label("total_count"),
            func.max(AuditEvent.created_at).label("last_seen"),
        )
        .where(*_filter_clauses(filters))
        .group_by(AuditEvent.action, AuditEvent.outcome)
        .order_by(desc("total_count"), desc("last_seen"))
        .limit(filters.limit)
        .offset(filters.offset)
    )
    rows = (await session.execute(statement)).all()
    return [
        AuditActionMetric(
            action=row.action,
            outcome=row.outcome,
            count=int(row.total_count),
            last_seen=row.last_seen,
        )
        for row in rows
    ]


async def _actor_metrics(
    session: AsyncSession,
    filters: AuditActivityFilter,
) -> list[AuditActorMetric]:
    failure_count = func.sum(case((AuditEvent.outcome == "failure", 1), else_=0))
    actor_hash = _actor_hash_group_expression()
    statement = (
        select(
            AuditEvent.actor_id,
            actor_hash.label("actor_email_hash"),
            func.count().label("count"),
            failure_count.label("failure_count"),
            func.max(AuditEvent.created_at).label("last_seen"),
        )
        .where(
            *_filter_clauses(filters),
            (AuditEvent.actor_id.is_not(None) | AuditEvent.actor_email_hash.is_not(None)),
        )
        .group_by(AuditEvent.actor_id, actor_hash)
        .order_by(desc("count"), desc("last_seen"))
        .limit(filters.limit)
        .offset(filters.offset)
    )
    rows = (await session.execute(statement)).all()
    return [
        AuditActorMetric(
            actor_id=row.actor_id,
            actor_email_hash=row.actor_email_hash,
            count=int(row.count),
            failure_count=int(row.failure_count or 0),
            last_seen=row.last_seen,
        )
        for row in rows
    ]


async def _recent_activity(
    session: AsyncSession,
    filters: AuditActivityFilter,
) -> list[RecentAuditActivity]:
    statement = (
        select(
            AuditEvent.action,
            AuditEvent.outcome,
            AuditEvent.resource,
            AuditEvent.correlation_id,
            AuditEvent.created_at,
        )
        .where(*_filter_clauses(filters))
        .order_by(desc(AuditEvent.created_at))
        .limit(filters.limit)
    )
    rows = (await session.execute(statement)).all()
    return [
        RecentAuditActivity(
            action=row.action,
            outcome=row.outcome,
            resource=row.resource,
            correlation_id=row.correlation_id,
            created_at=row.created_at,
        )
        for row in rows
    ]


async def _investigation_status_counts(
    session: AsyncSession,
    filters: AuditActivityFilter,
) -> Counter[str]:
    statement = (
        select(AuditEvent.metadata_["to_status"].as_string(), func.count())
        .where(
            *_filter_clauses(filters),
            AuditEvent.action == "detections.alert_updated",
            AuditEvent.outcome == "success",
        )
        .group_by(AuditEvent.metadata_["to_status"].as_string())
    )
    rows = (await session.execute(statement)).all()
    return Counter({str(status): int(count) for status, count in rows if status is not None})


def _tenant_scope_denials_statement(filters: AuditActivityFilter) -> Select[tuple[int]]:
    return (
        select(func.count())
        .select_from(AuditEvent)
        .where(
            *_filter_clauses(filters),
            AuditEvent.action == "auth.permission_denied",
            AuditEvent.metadata_["requested_tenant_id"].as_string().is_not(None),
        )
    )


def _is_tenant_scope_denial(metadata: dict[str, object]) -> bool:
    return metadata.get("requested_tenant_id") is not None


def _actor_key(event: AuditEventCreate) -> tuple[UUID | None, str | None]:
    if event.actor_id is not None:
        return event.actor_id, None
    return None, event.actor_email_hash


def _actor_hash_group_expression() -> ColumnElement[str | None]:
    return case((AuditEvent.actor_id.is_(None), AuditEvent.actor_email_hash), else_=None)


def _memory_investigation_status_counts(events: list[AuditEventCreate]) -> Counter[str]:
    return Counter(
        str(event.metadata["to_status"])
        for event in events
        if event.action.value == "detections.alert_updated"
        and event.outcome == "success"
        and event.metadata.get("to_status") is not None
    )
