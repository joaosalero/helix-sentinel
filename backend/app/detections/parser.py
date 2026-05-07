"""Pragmatic Sigma parser for metadata normalization."""

from typing import Any, cast

import yaml  # type: ignore[import-untyped]

from app.detections.schemas import (
    AttackTechnique,
    DetectionRuleMetadata,
    SigmaParseResult,
)
from app.detections.taxonomy import DetectionCategory, DetectionSeverity


class SigmaParseError(ValueError):
    """Raised when uploaded Sigma content is invalid or unsupported."""


class SigmaParser:
    """Parse Sigma YAML metadata without executing or translating rules."""

    def parse(self, content: str) -> SigmaParseResult:
        """Safely parse a Sigma YAML rule into normalized metadata."""
        try:
            loaded = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise SigmaParseError("Invalid Sigma YAML") from exc

        if not isinstance(loaded, dict):
            raise SigmaParseError("Sigma content must be a YAML mapping")

        rule = cast(dict[str, Any], loaded)
        title = _required_string(rule, "title")
        detection = rule.get("detection")
        if not isinstance(detection, dict) or not detection:
            raise SigmaParseError("Sigma rule must include a non-empty detection section")

        tags = _string_list(rule.get("tags"))
        attack = _attack_from_tags(tags)
        metadata = DetectionRuleMetadata(
            tags=tags,
            references=_string_list(rule.get("references")),
            false_positives=_string_list(rule.get("falsepositives")),
            author=_optional_string(rule.get("author")),
            license=_optional_string(rule.get("license")),
        )

        return SigmaParseResult(
            title=title,
            description=_optional_string(rule.get("description")),
            severity=_severity(rule.get("level")),
            category=_category(rule, tags),
            source=_source(rule),
            sigma_id=_optional_string(rule.get("id")),
            sigma_status=_optional_string(rule.get("status")),
            raw_rule=rule,
            detection=cast(dict[str, Any], detection),
            metadata=metadata,
            attack=attack,
        )


def _required_string(rule: dict[str, Any], key: str) -> str:
    value = rule.get(key)
    if not isinstance(value, str) or not value.strip():
        raise SigmaParseError(f"Sigma rule requires non-empty {key}")
    return value.strip()


def _optional_string(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [item.strip() for item in value if isinstance(item, str) and item.strip()]
    return []


def _severity(value: Any) -> DetectionSeverity:
    if not isinstance(value, str):
        return DetectionSeverity.MEDIUM
    normalized = value.lower()
    if normalized in {"informational", "info"}:
        return DetectionSeverity.INFORMATIONAL
    if normalized in {"low", "medium", "high", "critical"}:
        return DetectionSeverity(normalized)
    return DetectionSeverity.MEDIUM


def _category(rule: dict[str, Any], tags: list[str]) -> DetectionCategory:
    haystack = " ".join(
        [
            str(rule.get("logsource", "")).lower(),
            str(rule.get("title", "")).lower(),
            " ".join(tags).lower(),
        ]
    )
    if any(term in haystack for term in ("auth", "login", "logon")):
        return DetectionCategory.AUTHENTICATION
    if any(term in haystack for term in ("network", "dns", "proxy", "firewall")):
        return DetectionCategory.NETWORK
    if any(term in haystack for term in ("process", "endpoint", "windows", "linux", "edr")):
        return DetectionCategory.ENDPOINT
    if any(term in haystack for term in ("cloud", "aws", "azure", "gcp")):
        return DetectionCategory.CLOUD
    if any(term in haystack for term in ("ioc", "indicator", "hash", "malware")):
        return DetectionCategory.IOC
    if "audit" in haystack:
        return DetectionCategory.AUDIT
    return DetectionCategory.GENERIC


def _source(rule: dict[str, Any]) -> str | None:
    logsource = rule.get("logsource")
    if not isinstance(logsource, dict):
        return None
    product = _optional_string(logsource.get("product"))
    service = _optional_string(logsource.get("service"))
    category = _optional_string(logsource.get("category"))
    return ":".join(part for part in (product, service, category) if part) or None


def _attack_from_tags(tags: list[str]) -> list[AttackTechnique]:
    techniques: dict[str, AttackTechnique] = {}
    tactic: str | None = None
    for tag in tags:
        lower = tag.lower()
        if lower.startswith("attack."):
            value = tag.split(".", 1)[1]
            if value.startswith("t") and len(value) >= 5:
                technique_id = value.upper()
                techniques[technique_id] = AttackTechnique(
                    technique_id=technique_id,
                    tactic=tactic,
                )
            elif not value.startswith("t"):
                tactic = value.replace("_", "-")
    if tactic is not None:
        return [
            technique.model_copy(update={"tactic": technique.tactic or tactic})
            for technique in techniques.values()
        ]
    return list(techniques.values())
