"""Shared data models for scan results."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Bandit (B105/B106/B107) quotes the literal value in its message, e.g.
# "Possible hardcoded password: 'hunter2'". Findings end up in SARIF uploads,
# CI logs and the cloud dashboard, so the value must never be serialized.
_SECRET_LITERAL_RE = re.compile(
    r"(hardcoded password:\s*)(['\"])(.*)\2",
    re.IGNORECASE | re.DOTALL,
)


def redact_secret_literals(text: str) -> str:
    """Replace secret values that scanners echo back in finding messages."""
    return _SECRET_LITERAL_RE.sub(r"\1\2[REDACTED]\2", text)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class ScanType(str, Enum):
    SAST = "sast"
    DAST = "dast"
    SCA = "sca"
    SECRETS = "secrets"
    IAC = "iac"
    CONTAINER = "container"
    ML = "ml"
    MALWARE = "malware"
    PCI = "pci"


@dataclass
class Finding:
    title: str
    severity: Severity
    scan_type: ScanType
    tool: str
    file: str = ""
    line: int = 0
    column: int = 0
    description: str = ""
    cwe: str = ""
    cve: str = ""
    fix_guidance: str = ""
    rule_id: str = ""
    data_classification: str = "unset"
    references: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": redact_secret_literals(self.title),
            "severity": self.severity.value,
            "scan_type": self.scan_type.value,
            "tool": self.tool,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "description": redact_secret_literals(self.description),
            "cwe": self.cwe,
            "cve": self.cve,
            "fix_guidance": self.fix_guidance,
            "rule_id": self.rule_id,
            "data_classification": self.data_classification,
            "references": self.references,
        }


@dataclass
class ScanResult:
    tool: str
    scan_type: ScanType
    target: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    tool_available: bool = True
    raw_output: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        counts["total"] = len(self.findings)
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "scan_type": self.scan_type.value,
            "target": self.target,
            "tool_available": self.tool_available,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "metadata": self.metadata,
        }


@dataclass
class AggregatedReport:
    target: str
    results: list[ScanResult] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, Any]:
        all_findings: list[Finding] = []
        for r in self.results:
            all_findings.extend(r.findings)

        by_severity: dict[str, int] = {s.value: 0 for s in Severity}
        by_type: dict[str, int] = {t.value: 0 for t in ScanType}
        by_tool: dict[str, int] = {}

        for f in all_findings:
            by_severity[f.severity.value] += 1
            by_type[f.scan_type.value] += 1
            by_tool[f.tool] = by_tool.get(f.tool, 0) + 1

        return {
            "total_findings": len(all_findings),
            "by_severity": by_severity,
            "by_scan_type": by_type,
            "by_tool": by_tool,
            "tools_run": [r.tool for r in self.results],
            "tools_unavailable": [r.tool for r in self.results if not r.tool_available],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "summary": self.summary,
            "results": [r.to_dict() for r in self.results],
        }
