"""Tests for data models."""

from argus.models import AggregatedReport, Finding, ScanResult, ScanType, Severity


def test_finding_to_dict():
    f = Finding(
        title="SQL Injection",
        severity=Severity.HIGH,
        scan_type=ScanType.SAST,
        tool="semgrep",
        file="app/routes.py",
        line=42,
        description="User input used in raw SQL query",
        cwe="CWE-89",
    )
    d = f.to_dict()
    assert d["title"] == "SQL Injection"
    assert d["severity"] == "high"
    assert d["scan_type"] == "sast"
    assert d["tool"] == "semgrep"
    assert d["line"] == 42
    assert d["cwe"] == "CWE-89"


def test_scan_result_summary():
    result = ScanResult(tool="bandit", scan_type=ScanType.SAST, target="/app")
    result.findings = [
        Finding("A", Severity.CRITICAL, ScanType.SAST, "bandit"),
        Finding("B", Severity.HIGH, ScanType.SAST, "bandit"),
        Finding("C", Severity.HIGH, ScanType.SAST, "bandit"),
        Finding("D", Severity.LOW, ScanType.SAST, "bandit"),
    ]
    summary = result.summary
    assert summary["total"] == 4
    assert summary["critical"] == 1
    assert summary["high"] == 2
    assert summary["low"] == 1


def test_aggregated_report():
    r1 = ScanResult(tool="semgrep", scan_type=ScanType.SAST, target="/app")
    r1.findings = [Finding("XSS", Severity.HIGH, ScanType.SAST, "semgrep")]

    r2 = ScanResult(tool="trivy", scan_type=ScanType.SCA, target="/app")
    r2.findings = [
        Finding("CVE-2023-1234", Severity.CRITICAL, ScanType.SCA, "trivy"),
        Finding("CVE-2023-5678", Severity.MEDIUM, ScanType.SCA, "trivy"),
    ]

    report = AggregatedReport(target="/app", results=[r1, r2])
    summary = report.summary
    assert summary["total_findings"] == 3
    assert summary["by_severity"]["critical"] == 1
    assert summary["by_severity"]["high"] == 1
    assert summary["by_severity"]["medium"] == 1
    assert "semgrep" in summary["tools_run"]
    assert "trivy" in summary["tools_run"]


def test_unavailable_tool():
    result = ScanResult(tool="gitleaks", scan_type=ScanType.SECRETS, target="/app")
    result.tool_available = False
    result.errors = ["gitleaks is not installed"]

    report = AggregatedReport(target="/app", results=[result])
    assert "gitleaks" in report.summary["tools_unavailable"]
