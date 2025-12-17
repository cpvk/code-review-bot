import pytest
from pydantic import ValidationError

from src.config import ReviewConfig
from src.models import Finding, validate_findings


def test_finding_defaults_and_roundtrip():
    f = Finding.from_dict({"line_number": 12, "severity": "critical",
                           "category": "security", "confidence": 0.9})
    d = f.to_dict()
    assert d["line_number"] == 12 and d["severity"] == "critical"
    assert "file" not in d  # empty file omitted for dict compatibility


def test_finding_coerces_range_string_line():
    assert Finding.from_dict({"line_number": "10-20"}).line_number == 10


def test_finding_rejects_out_of_range_confidence():
    with pytest.raises(ValidationError):
        Finding.from_dict({"confidence": 1.5})


def test_validate_findings_drops_malformed():
    out = validate_findings([{"line_number": 1, "confidence": 0.5},
                             {"confidence": 9}, "nope"])
    assert len(out) == 1


def test_config_from_env_parses_passes_and_threshold():
    cfg = ReviewConfig.from_env({
        "GITHUB_REPOSITORY": "o/r", "PR_NUMBER": "7",
        "REVIEW_PASSES": "security, bug", "CONFIDENCE_THRESHOLD": "0.7",
        "LLM_PROVIDER": "openai", "OPENAI_API_KEY": "k",
    })
    assert cfg.pr_number == 7
    assert cfg.review_passes == ["security", "bug"]
    assert cfg.api_key_for_provider() == "k"
    assert cfg.to_legacy_dict()["repo"] == "o/r"


def test_config_rejects_bad_threshold():
    with pytest.raises(ValidationError):
        ReviewConfig(confidence_threshold=2.0)
