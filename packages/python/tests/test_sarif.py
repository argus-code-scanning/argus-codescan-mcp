"""Tests for SARIF export."""

from argus.formatters.sarif import aggregated_report_to_sarif


def test_sarif_basic_structure():
    report = {
        "target": "/app",
        "results": [
            {
                "tool": "semgrep",
                "findings": [
                    {
                        "title": "SQL Injection",
                        "severity": "high",
                        "scan_type": "sast",
                        "tool": "semgrep",
                        "file": "app/db.py",
                        "line": 10,
                        "description": "User input in SQL query",
                        "rule_id": "python.sql-injection",
                        "cwe": "CWE-89",
                        "fix_guidance": "Use parameterized queries",
                    }
                ],
            }
        ],
    }
    sarif = aggregated_report_to_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "argus-scan"
    assert len(run["results"]) == 1
    assert run["results"][0]["level"] == "error"
    assert (
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "app/db.py"
    )


def test_sarif_empty_report():
    sarif = aggregated_report_to_sarif({"target": "/app", "results": []})
    assert sarif["runs"][0]["results"] == []
