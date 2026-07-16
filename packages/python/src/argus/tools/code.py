"""Built-in multi-language code scanner (argus-languages integration)."""

from __future__ import annotations

import logging

from argus_languages import scan_directory as _scan_directory
from argus_languages.models import Severity as LangSeverity

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


async def run_native_languages(target: str) -> ScanResult:
    """Run built-in pattern scanner for Java, PHP, Terraform, Ansible, and all other languages."""
    result = ScanResult(tool="argus-languages", scan_type=ScanType.SAST, target=target)

    try:
        native = _scan_directory(target)
    except Exception as exc:
        logger.exception("argus-languages scan failed")
        result.errors.append(f"argus-languages error: {exc}")
        return result

    for item in native.findings:
        result.findings.append(
            Finding(
                title=item.title,
                severity=_SEV_MAP.get(item.severity, Severity.INFO),
                scan_type=ScanType.SAST,
                tool="argus-languages",
                file=item.file,
                line=item.line,
                description=item.description or f"Language: {item.language}",
                rule_id=item.rule_id,
            )
        )

    result.errors.extend(native.errors)
    result.metadata.update(native.metadata)
    return result
