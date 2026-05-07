"""Explainable deterministic scoring helpers for AI-assisted analytics."""

from statistics import mean, pstdev

from app.ai.schemas import ExplainabilityFactor
from app.ai.taxonomy import ConfidenceLevel
from app.events.taxonomy import EventSeverity

SEVERITY_WEIGHT: dict[EventSeverity, int] = {
    EventSeverity.INFO: 5,
    EventSeverity.LOW: 10,
    EventSeverity.MEDIUM: 20,
    EventSeverity.HIGH: 30,
    EventSeverity.CRITICAL: 40,
}


def z_score(value: float, baseline: list[float]) -> float:
    """Return a stable population z-score with safe low-sample behavior."""
    if len(baseline) < 2:
        return 0.0
    deviation = pstdev(baseline)
    if deviation == 0:
        return 0.0
    return (value - mean(baseline)) / deviation


def confidence(score: int, factor_count: int) -> ConfidenceLevel:
    """Map score and factor count to an explainable confidence band."""
    if score >= 70 and factor_count >= 2:
        return ConfidenceLevel.HIGH
    if score >= 35:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


def score_from_factors(factors: list[ExplainabilityFactor]) -> int:
    """Add deterministic factor points and cap the result at 100."""
    return min(sum(factor.points for factor in factors), 100)

