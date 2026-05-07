"""AI-assisted deterministic security analytics service."""

import logging
from collections import defaultdict
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
from app.events.taxonomy import EventSeverity

logger = logging.getLogger(__name__)


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
        enrichments = [_enrich_event(event) for event in events]
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
        anomaly_response = await self.anomalies(filters, correlation_id=None)
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
        for event in events:
            enrichment = _enrich_event(event)
            if enrichment.score < 35:
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


def _enrich_event(event: NormalizedEvent) -> AIEnrichment:
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
