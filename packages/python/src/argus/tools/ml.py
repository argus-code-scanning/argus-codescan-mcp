"""Built-in AI/ML model and LLM pipeline security scanner."""

from __future__ import annotations

import logging

from argus_languages.models import Severity as LangSeverity
from argus_languages.rules_loader import load_rules_from_files
from argus_languages.scanner import scan_path as _scan_path

from argus.models import Finding, ScanResult, ScanType, Severity

logger = logging.getLogger(__name__)

_SEV_MAP = {
    LangSeverity.CRITICAL: Severity.CRITICAL,
    LangSeverity.HIGH: Severity.HIGH,
    LangSeverity.MEDIUM: Severity.MEDIUM,
    LangSeverity.MODERATE: Severity.MEDIUM,
    LangSeverity.LOW: Severity.LOW,
    LangSeverity.INFO: Severity.INFO,
}

ML_RULE_FILES = ("ml.yaml",)


async def run_ml_scan(target: str) -> ScanResult:
    """Scan for AI/ML security issues: unsafe model loading, LLM keys, prompt injection, etc."""
    result = ScanResult(tool="argus-ml", scan_type=ScanType.ML, target=target)

    try:
        rules = load_rules_from_files(ML_RULE_FILES)
        native = _scan_path(target, rules=rules)
    except Exception as exc:
        logger.exception("argus-ml scan failed")
        result.errors.append(f"argus-ml error: {exc}")
        return result

    for item in native.findings:
        result.findings.append(
            Finding(
                title=item.title,
                severity=_SEV_MAP.get(item.severity, Severity.INFO),
                scan_type=ScanType.ML,
                tool="argus-ml",
                file=item.file,
                line=item.line,
                description=item.description or f"Language: {item.language}",
                rule_id=item.rule_id,
            )
        )

    result.errors.extend(native.errors)
    result.metadata.update(native.metadata)
    result.metadata["rule_pack"] = "ml"
    return result
