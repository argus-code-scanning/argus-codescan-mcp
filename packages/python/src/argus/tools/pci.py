"""Built-in PCI-DSS cardholder-data exposure heuristic scanner."""

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

PCI_RULE_FILES = ("pci-dss.yaml",)


async def run_pci_scan(target: str) -> ScanResult:
    """Scan for PCI-DSS cardholder-data exposure (CVV storage, PANs in logs, non-TLS card data)."""
    result = ScanResult(tool="argus-pci", scan_type=ScanType.PCI, target=target)

    try:
        rules = load_rules_from_files(PCI_RULE_FILES)
        if not rules:
            result.errors.append(
                "argus-pci error: no PCI-DSS rules loaded — the installed argus-languages "
                "does not include pci-dss.yaml. Upgrade argus-languages to get the PCI rule pack."
            )
            return result
        native = _scan_path(target, rules=rules)
    except Exception as exc:
        logger.exception("argus-pci scan failed")
        result.errors.append(f"argus-pci error: {exc}")
        return result

    for item in native.findings:
        result.findings.append(
            Finding(
                title=item.title,
                severity=_SEV_MAP.get(item.severity, Severity.INFO),
                scan_type=ScanType.PCI,
                tool="argus-pci",
                file=item.file,
                line=item.line,
                description=item.description
                or "Heuristic PCI-DSS cardholder-data pattern (static analysis — not a QSA assessment)",
                rule_id=item.rule_id,
                fix_guidance=(
                    "Remove or tokenize cardholder data. Never log PANs. Never store CVV/CVC "
                    "after authorization. Send card data only over HTTPS."
                ),
            )
        )

    result.errors.extend(native.errors)
    result.metadata.update(native.metadata)
    result.metadata["rule_pack"] = "pci-dss"
    result.metadata["rules_loaded"] = len(rules)
    return result
