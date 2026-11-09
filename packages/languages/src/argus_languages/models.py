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
    data_classification: str = "unset"
    fix_guidance: str = ""
    # How likely a match is a real issue: "high", "medium" or "low" (see rules_loader).
    confidence: str = "medium"
    # "" for normal source, or "test" / "docs" / "generated" when the path suggests the
    # code does not ship (the severity has then been lowered one level).
    context: str = ""

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
            "data_classification": self.data_classification,
            "fix_guidance": self.fix_guidance,
            "confidence": self.confidence,
            "context": self.context,
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
