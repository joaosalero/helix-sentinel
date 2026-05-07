"""Threat Analytics correlation service."""

import logging
from collections import defaultdict
from datetime import UTC, datetime
from time import perf_counter
from uuid import uuid4

from app.events.schemas import NormalizedEvent
from app.events.taxonomy import EventCategory
from app.threats.metrics import threat_correlation_duration_seconds, threat_correlations_total
from app.threats.repositories import ThreatEventRepository
from app.threats.schemas import (
    IOCReference,
    TemporalMetadata,
    ThreatAnalyticsFilter,
    ThreatInsight,
    ThreatInsightListResponse,
    ThreatSummary,
)
from app.threats.scoring import risk_level, score_events
from app.threats.taxonomy import IndicatorType, ThreatInsightType

logger = logging.getLogger(__name__)


class ThreatAnalyticsService:
    """Generate deterministic threat insights from normalized events."""

    def __init__(self, repository: ThreatEventRepository) -> None:
        self.repository = repository

    async def insights(
        self,
        filters: ThreatAnalyticsFilter,
        *,
        correlation_id: str | None,
    ) -> ThreatInsightListResponse:
        """Return filtered and paginated threat insights."""
        started = perf_counter()
        events = await self.repository.list_events(filters)
        generated = self._generate(events)
        filtered = _filter_insights(generated, filters)
        elapsed = perf_counter() - started
        threat_correlation_duration_seconds.labels(operation="insights").observe(elapsed)
        logger.info(
            "Threat insights generated",
            extra={
                "correlation_id": correlation_id,
                "insight_count": len(filtered),
                "elapsed_ms": round(elapsed * 1000, 2),
            },
        )
        return ThreatInsightListResponse(
            items=filtered[filters.offset : filters.offset + filters.limit],
            total=len(filtered),
            limit=filters.limit,
            offset=filters.offset,
        )

    async def summary(self, filters: ThreatAnalyticsFilter) -> ThreatSummary:
        """Return dashboard-ready summary counts for generated insights."""
        response = await self.insights(
            filters.model_copy(update={"limit": 100, "offset": 0}),
            correlation_id=None,
        )
        insights = response.items
        return ThreatSummary(
            total_insights=response.total,
            high_or_critical=sum(insight.risk_score >= 65 for insight in insights),
            ioc_related=sum(bool(insight.iocs) for insight in insights),
            repeated_auth_failures=sum(
                insight.insight_type == ThreatInsightType.REPEATED_AUTH_FAILURE
                for insight in insights
            ),
            suspicious_ip_reuse=sum(
                insight.insight_type == ThreatInsightType.SUSPICIOUS_IP_REUSE
                for insight in insights
            ),
            endpoint_repetition=sum(
                insight.insight_type == ThreatInsightType.ENDPOINT_REPETITION
                for insight in insights
            ),
            event_bursts=sum(
                insight.insight_type == ThreatInsightType.EVENT_BURST for insight in insights
            ),
            max_risk_score=max((insight.risk_score for insight in insights), default=0),
        )

    def _generate(self, events: list[NormalizedEvent]) -> list[ThreatInsight]:
        insights = [
            *self._repeated_auth_failures(events),
            *self._ioc_matches(events),
            *self._suspicious_ip_reuse(events),
            *self._endpoint_repetition(events),
            *self._event_bursts(events),
        ]
        insights.sort(
            key=lambda insight: (insight.risk_score, insight.temporal.last_seen),
            reverse=True,
        )
        for insight in insights:
            threat_correlations_total.labels(insight_type=insight.insight_type.value).inc()
        return insights

    def _repeated_auth_failures(self, events: list[NormalizedEvent]) -> list[ThreatInsight]:
        grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            if (
                event.category != EventCategory.AUTHENTICATION
                or not _looks_like_failure(event.title)
            ):
                continue
            key = event.actor.email or event.actor.username or event.actor.ip_address
            if key:
                grouped[key].append(event)
        return [
            _build_insight(
                ThreatInsightType.REPEATED_AUTH_FAILURE,
                "Repeated authentication failures",
                f"Multiple authentication failures observed for {key}.",
                related,
                suspicious_repetition=True,
                metadata={"entity": key},
            )
            for key, related in grouped.items()
            if len(related) >= 3
        ]

    def _ioc_matches(self, events: list[NormalizedEvent]) -> list[ThreatInsight]:
        insights: list[ThreatInsight] = []
        for event in events:
            iocs = _iocs_from_event(event)
            if not iocs:
                continue
            insights.append(
                _build_insight(
                    ThreatInsightType.IOC_MATCH,
                    "IOC-related security event",
                    "Security event contains IOC metadata prepared for enrichment.",
                    [event],
                    iocs=iocs,
                    has_ioc=True,
                )
            )
        return insights

    def _suspicious_ip_reuse(self, events: list[NormalizedEvent]) -> list[ThreatInsight]:
        grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            ip_address = event.actor.ip_address or event.network.get("source_ip")
            if isinstance(ip_address, str):
                grouped[ip_address].append(event)
        insights: list[ThreatInsight] = []
        for ip_address, related in grouped.items():
            actors = {event.actor.email or event.actor.username for event in related}
            actors.discard(None)
            if len(related) >= 3 and len(actors) >= 2:
                insights.append(
                    _build_insight(
                        ThreatInsightType.SUSPICIOUS_IP_REUSE,
                        "Suspicious IP reuse",
                        f"IP address {ip_address} appears across multiple actors.",
                        related,
                        suspicious_repetition=True,
                        metadata={"ip_address": ip_address, "actor_count": len(actors)},
                    )
                )
        return insights

    def _endpoint_repetition(self, events: list[NormalizedEvent]) -> list[ThreatInsight]:
        grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            if event.category != EventCategory.ENDPOINT:
                continue
            key = event.asset.hostname or event.asset.asset_id or event.asset.ip_address
            if key:
                grouped[key].append(event)
        return [
            _build_insight(
                ThreatInsightType.ENDPOINT_REPETITION,
                "Repeated endpoint anomaly",
                f"Repeated endpoint security events observed for {asset}.",
                related,
                suspicious_repetition=True,
                metadata={"asset": asset},
            )
            for asset, related in grouped.items()
            if len(related) >= 2
        ]

    def _event_bursts(self, events: list[NormalizedEvent]) -> list[ThreatInsight]:
        grouped: dict[tuple[str, EventCategory], list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            grouped[(event.source_name, event.category)].append(event)
        return [
            _build_insight(
                ThreatInsightType.EVENT_BURST,
                "Event frequency burst",
                f"Elevated {category.value} event volume from {source}.",
                related,
                suspicious_repetition=True,
                metadata={"source": source, "category": category.value},
            )
            for (source, category), related in grouped.items()
            if len(related) >= 5 and _window_minutes(related) <= 60
        ]


def _build_insight(
    insight_type: ThreatInsightType,
    title: str,
    description: str,
    events: list[NormalizedEvent],
    *,
    iocs: list[IOCReference] | None = None,
    has_ioc: bool = False,
    suspicious_repetition: bool = False,
    metadata: dict[str, object] | None = None,
) -> ThreatInsight:
    score, factors = score_events(
        events,
        has_ioc=has_ioc,
        suspicious_repetition=suspicious_repetition,
        attack_mapped=any(_has_attack_metadata(event) for event in events),
    )
    first_seen = min(event.event_time for event in events)
    last_seen = max(event.event_time for event in events)
    return ThreatInsight(
        id=uuid4(),
        insight_type=insight_type,
        title=title,
        description=description,
        risk_score=score,
        risk_level=risk_level(score),
        related_event_ids=[event.id for event in events],
        iocs=iocs or [],
        temporal=TemporalMetadata(
            first_seen=first_seen,
            last_seen=last_seen,
            event_count=len(events),
            window_minutes=_window_minutes(events),
        ),
        risk_factors=factors,
        metadata=metadata or {},
        generated_at=datetime.now(UTC),
    )


def _filter_insights(
    insights: list[ThreatInsight],
    filters: ThreatAnalyticsFilter,
) -> list[ThreatInsight]:
    return [
        insight
        for insight in insights
        if (filters.insight_type is None or insight.insight_type == filters.insight_type)
        and insight.risk_score >= filters.min_risk_score
        and _matches_ioc_filter(insight, filters)
    ]


def _matches_ioc_filter(insight: ThreatInsight, filters: ThreatAnalyticsFilter) -> bool:
    if filters.indicator_type is None and filters.indicator_value is None:
        return True
    for ioc in insight.iocs:
        type_matches = (
            filters.indicator_type is None or ioc.indicator_type == filters.indicator_type
        )
        value_matches = filters.indicator_value is None or ioc.value == filters.indicator_value
        if type_matches and value_matches:
            return True
    return False


def _iocs_from_event(event: NormalizedEvent) -> list[IOCReference]:
    iocs: list[IOCReference] = []
    indicator = event.ioc.get("indicator")
    indicator_type = event.ioc.get("indicator_type")
    file_hash = event.ioc.get("file_hash")
    if isinstance(indicator, str):
        parsed_type = _indicator_type(indicator_type, indicator)
        iocs.append(IOCReference(indicator_type=parsed_type, value=indicator))
    if isinstance(file_hash, str):
        iocs.append(IOCReference(indicator_type=IndicatorType.HASH, value=file_hash))
    return iocs


def _indicator_type(value: object, indicator: str) -> IndicatorType:
    if isinstance(value, str):
        normalized = value.lower()
        if normalized in {item.value for item in IndicatorType}:
            return IndicatorType(normalized)
    if indicator.startswith("http://") or indicator.startswith("https://"):
        return IndicatorType.URL
    if all(part.isdigit() for part in indicator.split(".") if part):
        return IndicatorType.IP
    return IndicatorType.DOMAIN


def _window_minutes(events: list[NormalizedEvent]) -> int:
    if not events:
        return 0
    first_seen = min(event.event_time for event in events)
    last_seen = max(event.event_time for event in events)
    return int((last_seen - first_seen).total_seconds() // 60)


def _looks_like_failure(title: str) -> bool:
    value = title.lower()
    return any(term in value for term in ("fail", "denied", "invalid", "locked"))


def _has_attack_metadata(event: NormalizedEvent) -> bool:
    attack = event.enrichment.get("attack")
    return isinstance(attack, list | dict)
