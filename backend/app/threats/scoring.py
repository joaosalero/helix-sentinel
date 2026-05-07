"""Deterministic and explainable threat risk scoring."""

from app.events.schemas import NormalizedEvent
from app.events.taxonomy import EventSeverity
from app.threats.schemas import RiskFactor
from app.threats.taxonomy import RiskLevel

SEVERITY_POINTS: dict[EventSeverity, int] = {
    EventSeverity.INFO: 5,
    EventSeverity.LOW: 10,
    EventSeverity.MEDIUM: 20,
    EventSeverity.HIGH: 30,
    EventSeverity.CRITICAL: 40,
}


def score_events(
    events: list[NormalizedEvent],
    *,
    has_ioc: bool = False,
    suspicious_repetition: bool = False,
    attack_mapped: bool = False,
) -> tuple[int, list[RiskFactor]]:
    """Score a correlated pattern using transparent additive factors."""
    factors: list[RiskFactor] = []
    max_severity = max((SEVERITY_POINTS[event.severity] for event in events), default=0)
    factors.append(
        RiskFactor(
            name="severity",
            points=max_severity,
            reason="Highest severity observed in the correlated event set.",
        )
    )

    frequency_points = min(len(events) * 5, 25)
    factors.append(
        RiskFactor(
            name="frequency",
            points=frequency_points,
            reason="Repeated events increase triage priority.",
        )
    )

    if suspicious_repetition:
        factors.append(
            RiskFactor(
                name="suspicious_repetition",
                points=15,
                reason="Pattern repeated around the same actor, asset, or source.",
            )
        )
    if has_ioc:
        factors.append(
            RiskFactor(
                name="ioc_relationship",
                points=20,
                reason="The pattern includes IOC metadata.",
            )
        )
    if attack_mapped:
        factors.append(
            RiskFactor(
                name="attack_mapping",
                points=10,
                reason="The event metadata references ATT&CK context.",
            )
        )

    return min(sum(factor.points for factor in factors), 100), factors


def risk_level(score: int) -> RiskLevel:
    """Map numeric score into a stable operational risk band."""
    if score >= 85:
        return RiskLevel.CRITICAL
    if score >= 65:
        return RiskLevel.HIGH
    if score >= 35:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW

