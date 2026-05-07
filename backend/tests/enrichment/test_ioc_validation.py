"""IOC validation tests."""

import pytest

from app.enrichment.taxonomy import IndicatorType
from app.enrichment.validators import normalize_indicator_value


@pytest.mark.parametrize(
    ("indicator_type", "value", "expected"),
    [
        (IndicatorType.IP, "203.0.113.10", "203.0.113.10"),
        (IndicatorType.DOMAIN, "Example.COM.", "example.com"),
        (IndicatorType.URL, "https://example.com/path?a=1", "https://example.com/path?a=1"),
        (
            IndicatorType.HASH,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
    ],
)
def test_supported_ioc_values_are_normalized(
    indicator_type: IndicatorType,
    value: str,
    expected: str,
) -> None:
    assert normalize_indicator_value(indicator_type, value) == expected


@pytest.mark.parametrize(
    ("indicator_type", "value"),
    [
        (IndicatorType.IP, "not-an-ip"),
        (IndicatorType.DOMAIN, "localhost"),
        (IndicatorType.DOMAIN, "-bad.example"),
        (IndicatorType.URL, "file:///etc/passwd"),
        (IndicatorType.URL, "http://127.0.0.1/admin"),
        (IndicatorType.URL, "http://localhost/admin"),
        (IndicatorType.URL, "https://10.0.0.10/internal"),
        (IndicatorType.HASH, "not-a-valid-hash"),
    ],
)
def test_invalid_or_ssrf_prone_ioc_values_are_rejected(
    indicator_type: IndicatorType,
    value: str,
) -> None:
    with pytest.raises(ValueError):
        normalize_indicator_value(indicator_type, value)
