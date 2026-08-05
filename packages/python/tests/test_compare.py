"""Tests for scan comparison / baseline diff."""

from argus.compare import compare_reports, finding_fingerprint, report_from_new_findings_only


def _finding(tool: str, rule_id: str, file: str, line: int = 1) -> dict:
    return {
        "tool": tool,
        "rule_id": rule_id,
        "title": rule_id,
        "file": file,
        "line": line,
        "severity": "high",
    }


def test_finding_fingerprint_stable():
    f = _finding("semgrep", "sql-inj", "app.py", 10)
    assert finding_fingerprint(f) == finding_fingerprint(f)


def test_compare_new_and_fixed():
    baseline = {
        "target": "/app",
        "results": [
            {
                "tool": "semgrep",
                "findings": [
                    _finding("semgrep", "old-rule", "a.py"),
                    _finding("semgrep", "kept-rule", "b.py"),
                ],
            }
        ],
    }
    current = {
        "target": "/app",
        "results": [
            {
                "tool": "semgrep",
                "findings": [
                    _finding("semgrep", "kept-rule", "b.py"),
                    _finding("semgrep", "new-rule", "c.py"),
                ],
            }
        ],
    }
    diff = compare_reports(baseline, current)
    assert diff["summary"]["new"] == 1
    assert diff["summary"]["fixed"] == 1
    assert diff["summary"]["unchanged"] == 1
    assert diff["new"][0]["rule_id"] == "new-rule"
    assert diff["fixed"][0]["rule_id"] == "old-rule"


def test_report_from_new_findings_only():
    baseline = {
        "target": "/app",
        "results": [
            {
                "tool": "semgrep",
                "findings": [_finding("semgrep", "old", "a.py")],
            }
        ],
    }
    current = {
        "target": "/app",
        "results": [
            {
                "tool": "semgrep",
                "findings": [
                    _finding("semgrep", "old", "a.py"),
                    _finding("semgrep", "new", "b.py"),
                ],
            }
        ],
    }
    report = report_from_new_findings_only(current, baseline)
    findings = report["results"][0]["findings"]
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "new"
