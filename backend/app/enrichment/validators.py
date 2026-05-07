"""Strict local IOC validation helpers.

The validators perform syntax checks only. They never resolve domains, fetch
URLs, query reputation services, or perform any outbound network activity.
"""

import ipaddress
import re
from urllib.parse import urlparse

from app.enrichment.taxonomy import IndicatorType

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)
HASH_PATTERN = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")


def normalize_indicator_value(indicator_type: IndicatorType, value: str) -> str:
    """Normalize and validate an IOC value without external lookups."""
    candidate = value.strip()
    if not candidate:
        msg = "indicator value must not be empty"
        raise ValueError(msg)
    if indicator_type == IndicatorType.IP:
        return str(ipaddress.ip_address(candidate))
    if indicator_type == IndicatorType.DOMAIN:
        normalized = candidate.rstrip(".").lower()
        if not DOMAIN_PATTERN.fullmatch(normalized):
            msg = "invalid domain indicator"
            raise ValueError(msg)
        return normalized
    if indicator_type == IndicatorType.URL:
        parsed = urlparse(candidate)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            msg = "invalid URL indicator"
            raise ValueError(msg)
        host = parsed.hostname or ""
        if not host or _is_localhost(host):
            msg = "URL indicator host is not allowed"
            raise ValueError(msg)
        return candidate
    if indicator_type == IndicatorType.HASH:
        normalized = candidate.lower()
        if not HASH_PATTERN.fullmatch(normalized):
            msg = "invalid hash indicator"
            raise ValueError(msg)
        return normalized
    msg = "unsupported indicator type"
    raise ValueError(msg)


def _is_localhost(host: str) -> bool:
    normalized = host.lower()
    if normalized in {"localhost", "localhost.localdomain"}:
        return True
    try:
        ip_address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return ip_address.is_loopback or ip_address.is_link_local or ip_address.is_private

