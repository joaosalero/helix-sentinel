"""Sigma parser tests."""

import pytest

from app.detections.parser import SigmaParseError, SigmaParser
from app.detections.taxonomy import DetectionCategory, DetectionSeverity

SIGMA_RULE = """
title: Suspicious PowerShell Execution
id: 8f7c2f10-1111-4444-8888-123456789abc
status: test
description: Detects suspicious PowerShell command usage.
author: SOC Team
references:
  - https://example.com/research
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
level: high
falsepositives:
  - Administrative scripts
detection:
  selection:
    Image|endswith: '\\powershell.exe'
  condition: selection
"""


def test_sigma_parser_extracts_metadata_and_attack_mapping() -> None:
    parsed = SigmaParser().parse(SIGMA_RULE)

    assert parsed.title == "Suspicious PowerShell Execution"
    assert parsed.severity == DetectionSeverity.HIGH
    assert parsed.category == DetectionCategory.ENDPOINT
    assert parsed.source == "windows:process_creation"
    assert parsed.metadata.author == "SOC Team"
    assert parsed.metadata.false_positives == ["Administrative scripts"]
    assert parsed.attack[0].technique_id == "T1059.001"
    assert parsed.attack[0].tactic == "execution"


def test_sigma_parser_rejects_malformed_yaml() -> None:
    with pytest.raises(SigmaParseError):
        SigmaParser().parse("title: [unterminated")


def test_sigma_parser_rejects_missing_detection() -> None:
    with pytest.raises(SigmaParseError):
        SigmaParser().parse("title: Missing Detection\nlevel: low\n")


def test_sigma_parser_uses_safe_loader() -> None:
    with pytest.raises(SigmaParseError):
        SigmaParser().parse("!!python/object/apply:os.system ['echo unsafe']")
