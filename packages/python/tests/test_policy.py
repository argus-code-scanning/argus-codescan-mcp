"""Tests for .argus.yml policy loading and filtering."""

from pathlib import Path

from argus.policy import PolicyConfig, apply_policy, load_policy


def test_load_policy_from_file(tmp_path: Path):
    policy_file = tmp_path / ".argus.yml"
    policy_file.write_text(
        """
fail_on: high
min_severity: medium
exclude_paths:
  - "tests/**"
suppressions:
  - rule_id: bandit.B101
    path: "tests/**"
    reason: test asserts
    expires: "2099-01-01"
"""
    )
    policy = load_policy(path=policy_file)
    assert policy.fail_on == "high"
    assert policy.min_severity == "medium"
    assert "tests/**" in policy.exclude_paths
    assert len(policy.suppressions) == 1


def test_apply_policy_excludes_paths():
    report = {
        "target": "/app",
        "results": [
            {
                "tool": "semgrep",
                "findings": [
                    {"severity": "high", "file": "src/main.py", "rule_id": "x"},
                    {"severity": "high", "file": "tests/test_main.py", "rule_id": "y"},
                ],
            }
        ],
    }
    policy = PolicyConfig(exclude_paths=["tests/**"])
    filtered = apply_policy(report, policy)
    findings = filtered["results"][0]["findings"]
    assert len(findings) == 1
    assert findings[0]["file"] == "src/main.py"


def test_apply_policy_suppression():
    report = {
        "target": "/app",
        "results": [
            {
                "tool": "bandit",
                "findings": [
                    {"severity": "low", "file": "tests/t.py", "rule_id": "bandit.B101"},
                    {"severity": "high", "file": "src/a.py", "rule_id": "bandit.B602"},
                ],
            }
        ],
    }
    from argus.policy import Suppression

    policy = PolicyConfig(
        suppressions=[Suppression(rule_id="bandit.B101", path="tests/**", expires="2099-01-01")]
    )
    filtered = apply_policy(report, policy)
    rule_ids = [f["rule_id"] for f in filtered["results"][0]["findings"]]
    assert "bandit.B101" not in rule_ids
    assert "bandit.B602" in rule_ids
