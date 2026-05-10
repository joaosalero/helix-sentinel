"""SOC analytics aggregation service."""

import logging
from time import perf_counter

from app.ai.schemas import AIAnalyticsSummary
from app.analytics.metrics import analytics_query_duration_seconds
from app.analytics.repositories import AnalyticsRepository
from app.analytics.schemas import (
    AlertWorkflowKpis,
    AnalyticsFilter,
    CountSummary,
    ExecutiveOperationalKpis,
    ExecutiveSecuritySummary,
    OperationalKpis,
    ReportingFinding,
    SocOverview,
    SocReport,
)
from app.detections.repositories import AlertReportingSnapshot
from app.detections.schemas import DetectionCoverageSummary
from app.events.taxonomy import EventCategory, EventSeverity
from app.threats.schemas import ThreatSummary

logger = logging.getLogger(__name__)


class SocAnalyticsService:
    """Coordinate SOC metric and KPI aggregations."""

    def __init__(self, repository: AnalyticsRepository) -> None:
        self.repository = repository

    async def overview(
        self,
        filters: AnalyticsFilter,
        *,
        correlation_id: str | None,
    ) -> SocOverview:
        """Build an operational overview for SOC dashboards."""
        started = perf_counter()
        total_events = await self.repository.total_events(filters)
        severity = await self.repository.severity_distribution(filters)
        categories = await self.repository.category_distribution(filters)
        trend = await self.repository.trend(filters)
        auth_failures = await self.repository.authentication_failures(filters)
        sources = await self.repository.source_metrics(filters)
        kpis = await self.kpis(filters)
        elapsed = perf_counter() - started
        analytics_query_duration_seconds.labels(operation="overview").observe(elapsed)
        logger.info(
            "SOC analytics overview calculated",
            extra={
                "correlation_id": correlation_id,
                "total_events": total_events,
                "elapsed_ms": round(elapsed * 1000, 2),
            },
        )
        return SocOverview(
            total_events=total_events,
            severity_distribution=severity,
            category_distribution=categories,
            ingestion_trend=trend,
            authentication_failures=auth_failures,
            top_sources=sources,
            kpis=kpis,
        )

    async def kpis(self, filters: AnalyticsFilter) -> OperationalKpis:
        """Calculate pragmatic SOC KPIs from currently available event data."""
        total = await self.repository.total_events(filters)
        severities = await self.repository.severity_distribution(filters)
        categories = await self.repository.category_distribution(filters)
        sources = await self.repository.source_metrics(
            filters.model_copy(update={"limit": 100, "offset": 0})
        )
        high_count = sum(
            item.count
            for item in severities
            if item.name in {EventSeverity.HIGH.value, EventSeverity.CRITICAL.value}
        )
        auth_count = next(
            (item.count for item in categories if item.name == EventCategory.AUTHENTICATION.value),
            0,
        )
        auth_failure_trend = await self.repository.authentication_failures(filters)
        auth_failures = sum(point.count for point in auth_failure_trend)
        return OperationalKpis(
            high_severity_ratio=round(high_count / total, 4) if total else 0.0,
            authentication_failure_ratio=(
                round(auth_failures / auth_count, 4) if auth_count else 0.0
            ),
            events_per_source=round(total / len(sources), 2) if sources else 0.0,
        )

    async def report(
        self,
        filters: AnalyticsFilter,
        *,
        alert_snapshot: AlertReportingSnapshot,
        threat_summary: ThreatSummary,
        ai_summary: AIAnalyticsSummary,
        correlation_id: str | None,
        detection_coverage: DetectionCoverageSummary | None = None,
    ) -> SocReport:
        """Build an executive and analyst-oriented SOC report."""
        started = perf_counter()
        total_events = await self.repository.total_events(filters)
        severity = await self.repository.severity_distribution(filters)
        categories = await self.repository.category_distribution(filters)
        sources = await self.repository.source_metrics(
            filters.model_copy(update={"limit": 10, "offset": 0})
        )
        kpis = await self.kpis(filters)
        high_count = _count_names(
            severity,
            {EventSeverity.HIGH.value, EventSeverity.CRITICAL.value},
        )
        alert_workflow = _alert_workflow_kpis(alert_snapshot)
        executive_kpis = _executive_kpis(
            operational_kpis=kpis,
            alert_workflow=alert_workflow,
            threat_summary=threat_summary,
            ai_summary=ai_summary,
            detection_coverage=detection_coverage,
        )
        findings = _report_findings(
            high_or_critical_events=high_count,
            total_events=total_events,
            alert_workflow=alert_workflow,
            threat_summary=threat_summary,
            ai_summary=ai_summary,
            detection_coverage=detection_coverage,
        )
        executive = _executive_summary(
            total_events=total_events,
            high_or_critical_events=high_count,
            alert_workflow=alert_workflow,
            threat_summary=threat_summary,
            ai_summary=ai_summary,
            active_sources=len(sources),
            executive_kpis=executive_kpis,
            findings=findings,
        )
        elapsed = perf_counter() - started
        analytics_query_duration_seconds.labels(operation="report").observe(elapsed)
        logger.info(
            "SOC report calculated",
            extra={
                "correlation_id": correlation_id,
                "total_events": total_events,
                "alert_volume": alert_workflow.alert_volume,
                "elapsed_ms": round(elapsed * 1000, 2),
            },
        )
        return SocReport(
            period_start=filters.start_time,
            period_end=filters.end_time,
            executive_summary=executive,
            operational_kpis=kpis,
            alert_workflow=alert_workflow,
            executive_kpis=executive_kpis,
            severity_distribution=severity,
            category_distribution=categories,
            top_sources=sources,
            threat_summary=threat_summary,
            ai_summary=ai_summary,
            findings=findings,
        )


def _alert_workflow_kpis(snapshot: AlertReportingSnapshot) -> AlertWorkflowKpis:
    closed = snapshot.closed_alerts
    return AlertWorkflowKpis(
        alert_volume=snapshot.total_alerts,
        open_alerts=snapshot.open_alerts,
        acknowledged_alerts=snapshot.acknowledged_alerts,
        closed_alerts=snapshot.closed_alerts,
        high_or_critical_alerts=snapshot.high_or_critical_alerts,
        unassigned_open_alerts=snapshot.unassigned_open_alerts,
        oldest_open_alert_minutes=snapshot.oldest_open_alert_minutes,
        mtta_minutes=snapshot.mtta_minutes,
        mttr_minutes=snapshot.mttr_minutes,
        true_positive_rate=(
            round(snapshot.true_positive_alerts / closed, 4) if closed else None
        ),
        false_positive_rate=(
            round(snapshot.false_positive_alerts / closed, 4) if closed else None
        ),
    )


def _executive_summary(
    *,
    total_events: int,
    high_or_critical_events: int,
    alert_workflow: AlertWorkflowKpis,
    threat_summary: ThreatSummary,
    ai_summary: AIAnalyticsSummary,
    active_sources: int,
    executive_kpis: ExecutiveOperationalKpis,
    findings: list[ReportingFinding],
) -> ExecutiveSecuritySummary:
    risk_score = _risk_score(executive_kpis)
    posture = _posture(risk_score)
    primary_driver = findings[0].name if findings else None
    return ExecutiveSecuritySummary(
        posture=posture,
        risk_score=risk_score,
        summary=_posture_summary(posture),
        primary_driver=primary_driver,
        total_events=total_events,
        high_or_critical_events=high_or_critical_events,
        alert_volume=alert_workflow.alert_volume,
        open_alerts=alert_workflow.open_alerts,
        high_or_critical_alerts=alert_workflow.high_or_critical_alerts,
        threat_insights=threat_summary.total_insights,
        high_or_critical_threat_insights=threat_summary.high_or_critical,
        ai_anomalies=ai_summary.total_anomalies,
        high_confidence_ai_anomalies=ai_summary.high_confidence,
        active_sources=active_sources,
    )


def _executive_kpis(
    *,
    operational_kpis: OperationalKpis,
    alert_workflow: AlertWorkflowKpis,
    threat_summary: ThreatSummary,
    ai_summary: AIAnalyticsSummary,
    detection_coverage: DetectionCoverageSummary | None,
) -> ExecutiveOperationalKpis:
    closed_or_open = alert_workflow.closed_alerts + alert_workflow.open_alerts
    return ExecutiveOperationalKpis(
        high_severity_ratio=operational_kpis.high_severity_ratio,
        authentication_failure_ratio=operational_kpis.authentication_failure_ratio,
        alert_closure_ratio=(
            round(alert_workflow.closed_alerts / closed_or_open, 4) if closed_or_open else 0.0
        ),
        open_alerts=alert_workflow.open_alerts,
        unassigned_open_alerts=alert_workflow.unassigned_open_alerts,
        mtta_minutes=alert_workflow.mtta_minutes,
        mttr_minutes=alert_workflow.mttr_minutes,
        true_positive_rate=alert_workflow.true_positive_rate,
        detection_coverage_ratio=(
            detection_coverage.coverage_ratio if detection_coverage is not None else None
        ),
        silent_active_rules=(
            detection_coverage.silent_active_rules if detection_coverage is not None else None
        ),
        high_or_critical_threat_insights=threat_summary.high_or_critical,
        high_confidence_ai_anomalies=ai_summary.high_confidence,
    )


def _risk_score(kpis: ExecutiveOperationalKpis) -> int:
    score = 0
    score += min(kpis.open_alerts * 8, 24)
    score += min(kpis.unassigned_open_alerts * 6, 18)
    score += min(kpis.high_or_critical_threat_insights * 12, 24)
    score += min(kpis.high_confidence_ai_anomalies * 8, 16)
    score += round(kpis.high_severity_ratio * 20)
    score += round(kpis.authentication_failure_ratio * 15)
    if kpis.detection_coverage_ratio is not None and kpis.detection_coverage_ratio < 0.5:
        score += 10
    if kpis.silent_active_rules:
        score += min(kpis.silent_active_rules * 2, 10)
    return min(score, 100)


def _posture(risk_score: int) -> str:
    if risk_score >= 45:
        return "elevated"
    if risk_score >= 15:
        return "guarded"
    return "nominal"


def _posture_summary(posture: str) -> str:
    if posture == "elevated":
        return "Material security activity requires leadership awareness and SOC follow-through."
    if posture == "guarded":
        return "Operational risk is present but currently bounded by active SOC workflows."
    return "No material SOC posture pressure is visible in the reporting window."


def _report_findings(
    *,
    high_or_critical_events: int,
    total_events: int,
    alert_workflow: AlertWorkflowKpis,
    threat_summary: ThreatSummary,
    ai_summary: AIAnalyticsSummary,
    detection_coverage: DetectionCoverageSummary | None = None,
) -> list[ReportingFinding]:
    findings: list[ReportingFinding] = []
    if high_or_critical_events:
        findings.append(
            ReportingFinding(
                name="high_severity_event_load",
                severity="high" if high_or_critical_events >= 5 else "medium",
                count=high_or_critical_events,
                reason="High or critical normalized events were observed in the report window.",
            )
        )
    if alert_workflow.open_alerts:
        findings.append(
            ReportingFinding(
                name="open_alert_queue",
                severity="high" if alert_workflow.high_or_critical_alerts else "medium",
                count=alert_workflow.open_alerts,
                reason="Persisted detection alerts remain open for analyst triage.",
            )
        )
    if threat_summary.high_or_critical:
        findings.append(
            ReportingFinding(
                name="high_risk_threat_insights",
                severity="high",
                count=threat_summary.high_or_critical,
                reason="Threat analytics generated high or critical risk insights.",
            )
        )
    if ai_summary.high_confidence:
        findings.append(
            ReportingFinding(
                name="high_confidence_ai_anomalies",
                severity="medium",
                count=ai_summary.high_confidence,
                reason="Deterministic AI analytics generated high-confidence anomalies.",
            )
        )
    if detection_coverage is not None and detection_coverage.coverage_ratio < 0.5:
        findings.append(
            ReportingFinding(
                name="low_detection_mapping",
                severity="medium",
                count=detection_coverage.unmapped_rules,
                reason="Less than half of detection rules are mapped to ATT&CK techniques.",
            )
        )
    if detection_coverage is not None and detection_coverage.silent_active_rules:
        findings.append(
            ReportingFinding(
                name="silent_active_rules",
                severity="medium",
                count=detection_coverage.silent_active_rules,
                reason="Active detection rules produced no alerts in the report window.",
            )
        )
    if total_events == 0:
        findings.append(
            ReportingFinding(
                name="no_security_events",
                severity="medium",
                count=0,
                reason="No normalized security events were observed in the report window.",
            )
        )
    return findings


def _count_names(items: list[CountSummary], names: set[str]) -> int:
    return sum(item.count for item in items if item.name in names)
