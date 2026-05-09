"""Lightweight deterministic NLP enrichment for security events."""

import re

from app.ai.schemas import ExplainabilityFactor
from app.ai.taxonomy import ClassificationLabel
from app.events.schemas import NormalizedEvent

SUSPICIOUS_TERMS = {
    "failed",
    "denied",
    "malware",
    "powershell",
    "encoded",
    "credential",
    "phishing",
    "suspicious",
    "blocked",
    "ransom",
}

TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9_.:/-]{3,}")


def extract_keywords(event: NormalizedEvent) -> list[str]:
    """Extract stable lowercase keywords from normalized event metadata."""
    text = " ".join(
        [
            event.title,
            event.source_name,
            event.source_product or "",
            event.source_vendor or "",
            event.category.value,
            " ".join(
                str(value)
                for value in event.actor.model_dump(exclude_none=True).values()
            ),
            " ".join(
                str(value)
                for value in event.asset.model_dump(exclude_none=True).values()
            ),
            " ".join(str(value) for value in event.network.values()),
            " ".join(str(value) for value in event.ioc.values()),
        ]
    )
    keywords = {token.lower() for token in TOKEN_PATTERN.findall(text)}
    return sorted(keywords)[:25]


def suspicious_terms(keywords: list[str]) -> list[str]:
    """Return suspicious terms observed in extracted keywords."""
    return sorted(term for term in keywords if term in SUSPICIOUS_TERMS)


def classify_event(
    event: NormalizedEvent,
    keywords: list[str],
) -> tuple[list[ClassificationLabel], list[ExplainabilityFactor]]:
    """Classify an event with transparent deterministic heuristics."""
    labels: list[ClassificationLabel] = []
    factors: list[ExplainabilityFactor] = []
    joined = " ".join(keywords)
    indicator = event.ioc.get("indicator")
    file_hash = event.ioc.get("file_hash")

    if isinstance(indicator, str) and indicator:
        labels.append(ClassificationLabel.IOC_RELATED)
        factors.append(
            ExplainabilityFactor(
                name="ioc_metadata",
                points=25,
                reason="Event contains IOC metadata.",
            )
        )
        if indicator.startswith(("http://", "https://")):
            labels.append(ClassificationLabel.SUSPICIOUS_URL)
    if isinstance(file_hash, str) and file_hash:
        labels.append(ClassificationLabel.IOC_RELATED)
        factors.append(
            ExplainabilityFactor(
                name="file_hash_indicator",
                points=20,
                reason="Event contains file hash IOC metadata.",
            )
        )
    if any(term in joined for term in ("http://", "https://", "url", "domain")):
        labels.append(ClassificationLabel.SUSPICIOUS_URL)
        factors.append(
            ExplainabilityFactor(
                name="url_or_domain_terms",
                points=15,
                reason="Event text contains URL or domain indicators.",
            )
        )
    if any(term in joined for term in ("email", "phishing", "@")):
        labels.append(ClassificationLabel.SUSPICIOUS_EMAIL)
        factors.append(
            ExplainabilityFactor(
                name="email_terms",
                points=15,
                reason="Event text contains email or phishing-oriented terms.",
            )
        )
    if any(term in joined for term in ("powershell", "encoded", "process")):
        labels.append(ClassificationLabel.SUSPICIOUS_PROCESS)
        factors.append(
            ExplainabilityFactor(
                name="process_terms",
                points=15,
                reason="Event text contains suspicious process terms.",
            )
        )
    if not labels:
        labels.append(ClassificationLabel.BENIGN_OR_UNKNOWN)
    return sorted(set(labels), key=lambda item: item.value), factors
