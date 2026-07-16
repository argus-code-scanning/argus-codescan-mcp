from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    MODERATE = "moderate"
    LOW = "low"
    INFO = "info"

    @classmethod
    def normalize(cls, value: str) -> Severity:
        v = value.lower()
        if v == "moderate":
            return cls.MEDIUM
        try:
            return cls(v)
        except ValueError:
            return cls.INFO


@dataclass
class Finding:
    title: str
    severity: Severity
    tool: str
    file: str = ""
    line: int = 0
    rule_id: str = ""
    description: str = ""
    language: str = ""

    def to_dict(self) -> dict[str, Any]:
        sev = self.severity.value
        if sev == "medium":
            sev = "moderate"
        return {
            "title": self.title,
            "severity": sev,
            "tool": self.tool,
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule_id,
            "description": self.description,
            "language": self.language,
        }


@dataclass
class ScanResult:
    tool: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "metadata": self.metadata,
        }
