from __future__ import annotations

from types import SimpleNamespace

import pytest

from agentsec.detectors.base import DetectorMetadata, DetectorRuleMetadata
from agentsec.detectors.explain import build_detector_explanation
from agentsec.threat_db import load_bundled_database


def _detector_with_rules(
    *rules: DetectorRuleMetadata,
) -> SimpleNamespace:
    return SimpleNamespace(
        id="test-detector",
        version="1",
        metadata=DetectorMetadata(
            description="Synthetic detector contract.",
            supported_inputs=("fixture",),
            campaign_ids=("campaign-1",),
            technique_ids=("technique-1",),
            source_references=("https://example.test/advisory",),
            limitations=("Synthetic limitation.",),
            remediation_url="https://example.test/remediation",
            not_scanned=("test.remote",),
            applicability="fixture_present",
            rules=rules,
        ),
    )


def test_explanation_rejects_duplicate_rule_ids() -> None:
    detector = _detector_with_rules(
        DetectorRuleMetadata(id="duplicate", technique_ids=("technique-1",)),
        DetectorRuleMetadata(id="duplicate", technique_ids=("technique-1",)),
    )

    with pytest.raises(ValueError, match="duplicate rule IDs"):
        build_detector_explanation(detector, load_bundled_database())


def test_explanation_rejects_rule_techniques_outside_detector_contract() -> None:
    detector = _detector_with_rules(
        DetectorRuleMetadata(id="rule", technique_ids=("missing-technique",)),
    )

    with pytest.raises(ValueError, match="undeclared technique IDs"):
        build_detector_explanation(detector, load_bundled_database())
