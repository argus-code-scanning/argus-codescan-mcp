"""Tests for secret remediation guidance."""

from argus.remediation.secrets import format_fix_guidance, lookup_remediation, remediation_to_dict


def test_aws_remediation():
    guide = lookup_remediation("AWSKeyDetector")
    assert "AWS" in guide.title
    text = format_fix_guidance("aws-access-key")
    assert "IAM" in text or "AWS" in text
    assert "1." in text


def test_github_remediation():
    guide = lookup_remediation("GitHubTokenDetector")
    assert "GitHub" in guide.title


def test_generic_fallback():
    guide = lookup_remediation("UnknownCustomDetector")
    assert guide.title == "Exposed Secret"


def test_remediation_to_dict():
    data = remediation_to_dict("PrivateKeyDetector")
    assert "steps" in data
    assert len(data["steps"]) >= 3
    assert "fix_guidance" in data
