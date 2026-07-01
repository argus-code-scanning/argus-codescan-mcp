"""Tests for utility functions."""

from argus.utils import format_markdown_report, is_tool_available, parse_json_output


def test_parse_json_output_valid():
    result = parse_json_output('{"key": "value"}')
    assert result == {"key": "value"}


def test_parse_json_output_list():
    result = parse_json_output('[{"a": 1}, {"b": 2}]')
    assert len(result) == 2


def test_parse_json_output_mixed():
    # JSON embedded in other text
    result = parse_json_output('Some preamble text\n{"key": "value"}\nmore text')
    assert result == {"key": "value"}


def test_parse_json_output_invalid():
    result = parse_json_output("not json at all")
    assert result is None


def test_is_tool_available_python():
    # Python should always be available in tests
    import sys

    assert (
        is_tool_available(sys.executable)
        or is_tool_available("python3")
        or is_tool_available("python")
    )


def test_format_markdown_report():
    report = {
        "target": "/myapp",
        "summary": {
            "total_findings": 2,
            "by_severity": {
                "critical": 0,
                "high": 1,
                "medium": 1,
                "low": 0,
                "info": 0,
                "unknown": 0,
            },
            "by_scan_type": {"sast": 2},
            "by_tool": {"semgrep": 2},
            "tools_run": ["semgrep"],
            "tools_unavailable": [],
        },
        "results": [
            {
                "tool": "semgrep",
                "scan_type": "sast",
                "target": "/myapp",
                "tool_available": True,
                "summary": {"total": 2, "high": 1, "medium": 1},
                "findings": [
                    {
                        "title": "SQL Injection",
                        "severity": "high",
                        "file": "app/db.py",
                        "line": 10,
                        "scan_type": "sast",
                        "tool": "semgrep",
                        "description": "Raw SQL",
                        "cwe": "",
                        "cve": "",
                        "fix_guidance": "",
                        "rule_id": "",
                        "references": [],
                        "column": 0,
                    }
                ],
                "errors": [],
                "metadata": {},
            }
        ],
    }
    md = format_markdown_report(report)
    assert "# Security Scan Report" in md
    assert "/myapp" in md
    assert "semgrep" in md
    assert "SQL Injection" in md
