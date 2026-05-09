"""AI-assisted deterministic security analytics service."""

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from time import perf_counter
from uuid import uuid4

from app.ai.metrics import ai_anomalies_generated_total, ai_scoring_duration_seconds
from app.ai.nlp import classify_event, extract_keywords, suspicious_terms
from app.ai.repositories import AIEventRepository
from app.ai.schemas import (
    AIAnalyticsFilter,
    AIAnalyticsSummary,
    AIEnrichment,
    AnomalyFinding,
    AnomalyListResponse,
    EnrichmentListResponse,
    ExplainabilityFactor,
)
from app.ai.scoring import SEVERITY_WEIGHT, confidence, score_from_factors, z_score
from app.ai.taxonomy import AnomalyType, ClassificationLabel
from app.events.schemas import NormalizedEvent
from app.events.taxonomy import EventCategory, EventSeverity

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AnalyticsContext:
    """Deterministic peer context for one bounded scoring window."""

    actor_counts: Counter[str]
    asset_counts: Counter[str]
    source_category_counts: Counter[tuple[str, str]]
    high_severity_by_source: Counter[str]
    total_by_source: Counter[str]


class AIAnalyticsService:
    """Generate explainable AI-assisted analytics from normalized events."""

    def __init__(self, repository: AIEventRepository) -> None:
        self.repository = repository

    async def anomalies(
        self,
        filters: AIAnalyticsFilter,
        *,
        correlation_id: str | None,
    ) -> AnomalyListResponse:
        """Return deterministic anomaly findings with explainability metadata."""
        started = perf_counter()
        events = await self.repository.list_events(filters)
        findings = self._find_anomalies(events)
        filtered = _filter_anomalies(findings, filters)
        elapsed = perf_counter() - started
        ai_scoring_duration_seconds.labels(operation="anomalies").observe(elapsed)
        logger.info(
            "AI-assisted anomaly scoring completed",
            extra={
                "correlation_id": correlation_id,
                "finding_count": len(filtered),
                "elapsed_ms": round(elapsed * 1000, 2),
            },
        )
        return AnomalyListResponse(
            items=filtered[filters.offset : filters.offset + filters.limit],
            total=len(filtered),
            limit=filters.limit,
            offset=filters.offset,
        )

    async def enrichments(self, filters: AIAnalyticsFilter) -> EnrichmentListResponse:
        """Return deterministic NLP/classification enrichment for events."""
        events = await self.repository.list_events(filters)
        context = _analytics_context(events)
        enrichments = [_enrich_event(event, context) for event in events]
        filtered = [
            enrichment
            for enrichment in enrichments
            if (
                filters.classification is None
                or filters.classification in enrichment.classifications
            )
            and enrichment.score >= filters.min_score
        ]
        return EnrichmentListResponse(
            items=filtered[filters.offset : filters.offset + filters.limit],
            total=len(filtered),
            limit=filters.limit,
            offset=filters.offset,
        )

    async def summary(self, filters: AIAnalyticsFilter) -> AIAnalyticsSummary:
        """Return dashboard-ready AI analytics summary."""
        anomaly_response = await self.anomalies(
            filters.model_copy(update={"limit": 100, "offset": 0}),
            correlation_id=None,
        )
        enrichment_response = await self.enrichments(
            filters.model_copy(update={"limit": 100, "offset": 0})
        )
        anomalies = anomaly_response.items
        enrichments = enrichment_response.items
        return AIAnalyticsSummary(
            total_anomalies=anomaly_response.total,
            high_confidence=sum(item.confidence.value == "high" for item in anomalies),
            max_score=max((item.score for item in anomalies), default=0),
            suspicious_classifications=sum(
                any(
                    label != ClassificationLabel.BENIGN_OR_UNKNOWN
                    for label in item.classifications
                )
                for item in enrichments
            ),
            enriched_events=enrichment_response.total,
        )

    def _find_anomalies(self, events: list[NormalizedEvent]) -> list[AnomalyFinding]:
        findings = [
            *self._frequency_anomalies(events),
            *self._severity_anomalies(events),
            *self._event_bursts(events),
            *self._entity_concentration_anomalies(events),
            *self._low_and_slow_anomalies(events),
            *self._classification_anomalies(events),
        ]
        findings.sort(key=lambda item: (item.score, item.last_seen), reverse=True)
        for finding in findings:
            ai_anomalies_generated_total.labels(anomaly_type=finding.anomaly_type.value).inc()
        return findings

    def _frequency_anomalies(self, events: list[NormalizedEvent]) -> list[AnomalyFinding]:
        grouped: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            grouped[(event.source_name, event.category.value)].append(event)
        counts = [len(group) for group in grouped.values()]
        findings: list[AnomalyFinding] = []
        for (source, category), related in grouped.items():
            score = z_score(len(related), [float(count) for count in counts])
            if len(related) < 3 and score < 1.5:
                continue
            factors = [
                ExplainabilityFactor(
                    name="frequency_deviation",
                    points=min(int(max(score, 0) * 20) + len(related) * 4, 60),
                    reason="Event volume is elevated compared with peer source/category groups.",
                    metadata={"z_score": round(score, 4), "event_count": len(related)},
                )
            ]
            findings.append(
                _finding(
                    AnomalyType.FREQUENCY,
                    "Frequency anomaly",
                    f"Elevated {category} event frequency from {source}.",
                    related,
                    factors,
                )
            )
        return findings

    def _severity_anomalies(self, events: list[NormalizedEvent]) -> list[AnomalyFinding]:
        grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            grouped[event.source_name].append(event)
        findings: list[AnomalyFinding] = []
        for source, related in grouped.items():
            weights = [SEVERITY_WEIGHT[event.severity] for event in related]
            high_count = sum(
                event.severity in {EventSeverity.HIGH, EventSeverity.CRITICAL}
                for event in related
            )
            if not related or high_count == 0:
                continue
            avg_weight = sum(weights) / len(weights)
            if avg_weight < 25 and high_count < 2:
                continue
            factors = [
                ExplainabilityFactor(
                    name="severity_concentration",
                    points=min(int(avg_weight) + high_count * 10, 70),
                    reason="High-severity events are concentrated for this source.",
                    metadata={"source": source, "high_or_critical": high_count},
                )
            ]
            findings.append(
                _finding(
                    AnomalyType.SEVERITY,
                    "Severity anomaly",
                    f"High-severity concentration observed for {source}.",
                    related,
                    factors,
                )
            )
        return findings

    def _event_bursts(self, events: list[NormalizedEvent]) -> list[AnomalyFinding]:
        grouped: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            grouped[(event.source_name, event.category.value)].append(event)
        findings: list[AnomalyFinding] = []
        for (source, category), related in grouped.items():
            if len(related) < 5 or _window_minutes(related) > 60:
                continue
            factors = [
                ExplainabilityFactor(
                    name="short_window_burst",
                    points=min(35 + len(related) * 5, 75),
                    reason="Multiple related events occurred within a short time window.",
                    metadata={
                        "window_minutes": _window_minutes(related),
                        "event_count": len(related),
                    },
                )
            ]
            findings.append(
                _finding(
                    AnomalyType.EVENT_BURST,
                    "Event burst anomaly",
                    f"Short-window burst of {category} events from {source}.",
                    related,
                    factors,
                )
            )
        return findings

    def _classification_anomalies(self, events: list[NormalizedEvent]) -> list[AnomalyFinding]:
        findings: list[AnomalyFinding] = []
        context = _analytics_context(events)
        for event in events:
            enrichment = _enrich_event(event, context)
            if (
                enrichment.score < 35
                or ClassificationLabel.BENIGN_OR_UNKNOWN in enrichment.classifications
            ):
                continue
            findings.append(
                _finding(
                    AnomalyType.SUSPICIOUS_CLASSIFICATION,
                    "Suspicious classification",
                    "Event matched deterministic suspicious classification heuristics.",
                    [event],
                    enrichment.factors,
                    metadata={
                        "classifications": [
                            label.value for label in enrichment.classifications
                        ]
                    },
                )
            )
        return findings

    def _entity_concentration_anomalies(
        self,
        events: list[NormalizedEvent],
    ) -> list[AnomalyFinding]:
        findings: list[AnomalyFinding] = []
        for entity_type, grouped in (
            ("actor", _group_by_actor(events)),
            ("asset", _group_by_asset(events)),
        ):
            for entity, related in grouped.items():
                if len(related) < 3:
                    continue
                category_count = len({event.category for event in related})
                source_count = len({event.source_name for event in related})
                high_count = _high_or_critical_count(related)
                factors = [
                    ExplainabilityFactor(
                        name=f"{entity_type}_event_concentration",
                        points=min(20 + len(related) * 5, 45),
                        reason="Multiple events concentrate around one investigation entity.",
                        metadata={
                            "entity_type": entity_type,
                            "event_count": len(related),
                        },
                    )
                ]
                if category_count >= 2:
                    factors.append(
                        ExplainabilityFactor(
                            name="multi_category_context",
                            points=15,
                            reason="The entity appears across multiple event categories.",
                            metadata={"category_count": category_count},
                        )
                    )
                if source_count >= 2:
                    factors.append(
                        ExplainabilityFactor(
                            name="multi_source_context",
                            points=10,
                            reason="The entity appears across multiple telemetry sources.",
                            metadata={"source_count": source_count},
                        )
                    )
                if high_count:
                    factors.append(
                        ExplainabilityFactor(
                            name="entity_severity_context",
                            points=min(high_count * 8, 25),
                            reason="The entity has high or critical severity activity.",
                            metadata={"high_or_critical": high_count},
                        )
                    )
                findings.append(
                    _finding(
                        AnomalyType.ENTITY_CONCENTRATION,
                        "Entity concentration anomaly",
                        f"Repeated security activity concentrates around {entity_type} {entity}.",
                        related,
                        factors,
                        metadata={"entity_type": entity_type, "entity": entity},
                    )
                )
        return findings

    def _low_and_slow_anomalies(self, events: list[NormalizedEvent]) -> list[AnomalyFinding]:
        findings: list[AnomalyFinding] = []
        for key, grouped in (
            ("actor", _group_by_actor(events)),
            ("asset", _group_by_asset(events)),
        ):
            for entity, related in grouped.items():
                window_minutes = _window_minutes(related)
                if len(related) < 3 or window_minutes <= 60:
                    continue
                suspicious_count = sum(_looks_suspicious(event) for event in related)
                high_count = _high_or_critical_count(related)
                if suspicious_count < 2 and high_count == 0:
                    continue
                factors = [
                    ExplainabilityFactor(
                        name="extended_temporal_pattern",
                        points=min(20 + len(related) * 4, 45),
                        reason="Related activity spans a longer investigation window.",
                        metadata={
                            "entity_type": key,
                            "event_count": len(related),
                            "window_minutes": window_minutes,
                        },
                    )
                ]
                if suspicious_count:
                    factors.append(
                        ExplainabilityFactor(
                            name="repeated_suspicious_terms",
                            points=min(suspicious_count * 8, 25),
                            reason="Suspicious deterministic terms recur across the sequence.",
                            metadata={"suspicious_event_count": suspicious_count},
                        )
                    )
                if high_count:
                    factors.append(
                        ExplainabilityFactor(
                            name="low_and_slow_severity",
                            points=min(high_count * 10, 25),
                            reason="The longer sequence includes high-severity events.",
                            metadata={"high_or_critical": high_count},
                        )
                    )
                findings.append(
                    _finding(
                        AnomalyType.LOW_AND_SLOW,
                        "Low-and-slow activity anomaly",
                        f"Extended suspicious activity observed for {key} {entity}.",
                        related,
                        factors,
                        metadata={"entity_type": key, "entity": entity},
                    )
                )
        return findings


def _enrich_event(
    event: NormalizedEvent,
    context: AnalyticsContext | None = None,
) -> AIEnrichment:
    keywords = extract_keywords(event)
    terms = suspicious_terms(keywords)
    labels, factors = classify_event(event, keywords)
    if terms:
        factors.append(
            ExplainabilityFactor(
                name="suspicious_terms",
                points=min(len(terms) * 10, 30),
                reason="Suspicious security terms were extracted from event metadata.",
                metadata={"terms": terms},
            )
        )
    factors.extend(_operational_context_factors(event, context))
    score = score_from_factors(factors)
    return AIEnrichment(
        event_id=event.id,
        keywords=keywords,
        suspicious_terms=terms,
        classifications=labels,
        confidence=confidence(score, len(factors)),
        score=score,
        factors=factors,
    )


def _finding(
    anomaly_type: AnomalyType,
    title: str,
    description: str,
    events: list[NormalizedEvent],
    factors: list[ExplainabilityFactor],
    metadata: dict[str, object] | None = None,
) -> AnomalyFinding:
    score = score_from_factors(factors)
    first_seen = min(event.event_time for event in events)
    last_seen = max(event.event_time for event in events)
    return AnomalyFinding(
        id=uuid4(),
        anomaly_type=anomaly_type,
        title=title,
        description=description,
        score=score,
        confidence=confidence(score, len(factors)),
        event_ids=[event.id for event in events],
        category=events[0].category,
        first_seen=first_seen,
        last_seen=last_seen,
        factors=factors,
        metadata=metadata or {},
        generated_at=datetime.now(UTC),
    )


def _filter_anomalies(
    findings: list[AnomalyFinding],
    filters: AIAnalyticsFilter,
) -> list[AnomalyFinding]:
    return [
        finding
        for finding in findings
        if (filters.anomaly_type is None or finding.anomaly_type == filters.anomaly_type)
        and finding.score >= filters.min_score
    ]


def _window_minutes(events: list[NormalizedEvent]) -> int:
    if not events:
        return 0
    first_seen = min(event.event_time for event in events)
    last_seen = max(event.event_time for event in events)
    return int((last_seen - first_seen).total_seconds() // 60)


def _analytics_context(events: list[NormalizedEvent]) -> AnalyticsContext:
    actor_counts: Counter[str] = Counter()
    asset_counts: Counter[str] = Counter()
    source_category_counts: Counter[tuple[str, str]] = Counter()
    high_severity_by_source: Counter[str] = Counter()
    total_by_source: Counter[str] = Counter()
    for event in events:
        if actor := _actor_key(event):
            actor_counts[actor] += 1
        if asset := _asset_key(event):
            asset_counts[asset] += 1
        source_category_counts[(event.source_name, event.category.value)] += 1
        total_by_source[event.source_name] += 1
        if event.severity in {EventSeverity.HIGH, EventSeverity.CRITICAL}:
            high_severity_by_source[event.source_name] += 1
    return AnalyticsContext(
        actor_counts=actor_counts,
        asset_counts=asset_counts,
        source_category_counts=source_category_counts,
        high_severity_by_source=high_severity_by_source,
        total_by_source=total_by_source,
    )


def _operational_context_factors(
    event: NormalizedEvent,
    context: AnalyticsContext | None,
) -> list[ExplainabilityFactor]:
    factors: list[ExplainabilityFactor] = []
    severity_points = {
        EventSeverity.MEDIUM: 8,
        EventSeverity.HIGH: 15,
        EventSeverity.CRITICAL: 25,
    }.get(event.severity, 0)
    if severity_points:
        factors.append(
            ExplainabilityFactor(
                name="event_severity_context",
                points=severity_points,
                reason="Event severity increases analyst triage relevance.",
                metadata={"severity": event.severity.value},
            )
        )
    if event.category == EventCategory.AUTHENTICATION and _looks_like_failure(event.title):
        factors.append(
            ExplainabilityFactor(
                name="authentication_failure_context",
                points=12,
                reason="Authentication failure language is present in the event title.",
            )
        )
    if event.ioc and event.severity in {EventSeverity.HIGH, EventSeverity.CRITICAL}:
        factors.append(
            ExplainabilityFactor(
                name="ioc_severity_context",
                points=15,
                reason="IOC metadata appears on a high-severity event.",
            )
        )
    if context is None:
        return factors
    source_category_count = context.source_category_counts[
        (event.source_name, event.category.value)
    ]
    if source_category_count >= 5:
        factors.append(
            ExplainabilityFactor(
                name="source_category_volume_context",
                points=10,
                reason="The event belongs to an elevated source/category group.",
                metadata={"source_category_event_count": source_category_count},
            )
        )
    if actor := _actor_key(event):
        count = context.actor_counts[actor]
        if count >= 3:
            factors.append(
                ExplainabilityFactor(
                    name="actor_repetition_context",
                    points=min(10 + count * 3, 25),
                    reason="The actor appears repeatedly in the scoring window.",
                    metadata={"actor_event_count": count},
                )
            )
    if asset := _asset_key(event):
        count = context.asset_counts[asset]
        if count >= 3:
            factors.append(
                ExplainabilityFactor(
                    name="asset_repetition_context",
                    points=min(10 + count * 3, 25),
                    reason="The asset appears repeatedly in the scoring window.",
                    metadata={"asset_event_count": count},
                )
            )
    source_total = context.total_by_source[event.source_name]
    if source_total >= 3:
        high_ratio = context.high_severity_by_source[event.source_name] / source_total
        if high_ratio >= 0.5:
            factors.append(
                ExplainabilityFactor(
                    name="source_severity_ratio_context",
                    points=12,
                    reason="This source has a high concentration of severe events.",
                    metadata={"high_severity_ratio": round(high_ratio, 4)},
                )
            )
    return factors


def _group_by_actor(events: list[NormalizedEvent]) -> dict[str, list[NormalizedEvent]]:
    grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if key := _actor_key(event):
            grouped[key].append(event)
    return grouped


def _group_by_asset(events: list[NormalizedEvent]) -> dict[str, list[NormalizedEvent]]:
    grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if key := _asset_key(event):
            grouped[key].append(event)
    return grouped


def _actor_key(event: NormalizedEvent) -> str | None:
    return (
        event.actor.email
        or event.actor.username
        or event.actor.user_id
        or event.actor.ip_address
    )


def _asset_key(event: NormalizedEvent) -> str | None:
    return event.asset.hostname or event.asset.asset_id or event.asset.ip_address


def _high_or_critical_count(events: list[NormalizedEvent]) -> int:
    return sum(event.severity in {EventSeverity.HIGH, EventSeverity.CRITICAL} for event in events)


def _looks_suspicious(event: NormalizedEvent) -> bool:
    value = event.title.lower()
    return any(
        term in value
        for term in (
            "blocked",
            "credential",
            "denied",
            "encoded",
            "fail",
            "malware",
            "phishing",
            "powershell",
            "suspicious",
        )
    )


def _looks_like_failure(title: str) -> bool:
    value = title.lower()
    return any(term in value for term in ("fail", "denied", "invalid", "locked"))
