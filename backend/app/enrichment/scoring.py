"""Deterministic IOC confidence scoring."""

from datetime import UTC, datetime

from app.enrichment.schemas import ConfidenceFactor, IOCRecord
from app.enrichment.taxonomy import IndicatorType, IOCSeverity, SourceReliability

RELIABILITY_POINTS: dict[SourceReliability, int] = {
    SourceReliability.LOW: 5,
    SourceReliability.MEDIUM: 15,
    SourceReliability.HIGH: 25,
    SourceReliability.VERIFIED: 35,
}

SEVERITY_POINTS: dict[IOCSeverity, int] = {
    IOCSeverity.LOW: 5,
    IOCSeverity.MEDIUM: 10,
    IOCSeverity.HIGH: 20,
    IOCSeverity.CRITICAL: 30,
}

TYPE_POINTS: dict[IndicatorType, int] = {
    IndicatorType.IP: 10,
    IndicatorType.DOMAIN: 12,
    IndicatorType.URL: 15,
    IndicatorType.HASH: 18,
}


def score_ioc_match(
    ioc: IOCRecord,
    matched_fields: list[str],
) -> tuple[int, list[ConfidenceFactor]]:
    """Calculate explainable match confidence for an IOC/event relationship."""
    factors = [
        ConfidenceFactor(
            name="base_confidence",
            points=min(ioc.confidence, 40),
            reason="Configured IOC confidence contributes to match confidence.",
            metadata={"configured_confidence": ioc.confidence},
        ),
        ConfidenceFactor(
            name="source_reliability",
            points=RELIABILITY_POINTS[ioc.source_reliability],
            reason="More reliable sources increase confidence.",
            metadata={"source_reliability": ioc.source_reliability.value},
        ),
        ConfidenceFactor(
            name="severity",
            points=SEVERITY_POINTS[ioc.severity],
            reason="Higher-severity IOCs carry more operational weight.",
            metadata={"severity": ioc.severity.value},
        ),
        ConfidenceFactor(
            name="indicator_type",
            points=TYPE_POINTS[ioc.indicator_type],
            reason="Indicator type affects confidence based on expected specificity.",
            metadata={"indicator_type": ioc.indicator_type.value},
        ),
        ConfidenceFactor(
            name="match_context",
            points=min(len(matched_fields) * 5, 15),
            reason="Matching across more event fields increases confidence.",
            metadata={"matched_fields": matched_fields},
        ),
    ]
    recency_points = _recency_points(ioc)
    if recency_points:
        factors.append(
            ConfidenceFactor(
                name="recency",
                points=recency_points,
                reason="Recently observed IOCs receive a confidence boost.",
                metadata={"last_seen": ioc.last_seen.isoformat()},
            )
        )
    return min(sum(factor.points for factor in factors), 100), factors


def _recency_points(ioc: IOCRecord) -> int:
    age_days = (datetime.now(UTC) - ioc.last_seen).days
    if age_days <= 7:
        return 10
    if age_days <= 30:
        return 5
    return 0
