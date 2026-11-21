"""Built-in PCI-DSS cardholder-data exposure heuristic scanner."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from argus_languages.models import Severity as LangSeverity
from argus_languages.rules_loader import load_rules_from_files
from argus_languages.scanner import scan_path as _scan_path

from argus.models import Finding, ScanResult, ScanType, Severity
from argus.utils import luhn_valid

logger = logging.getLogger(__name__)

_SEV_MAP = {
    LangSeverity.CRITICAL: Severity.CRITICAL,
    LangSeverity.HIGH: Severity.HIGH,
    LangSeverity.MEDIUM: Severity.MEDIUM,
    LangSeverity.MODERATE: Severity.MEDIUM,
    LangSeverity.LOW: Severity.LOW,
    LangSeverity.INFO: Severity.INFO,
}

PCI_RULE_FILES = ("pci-dss.yaml", "pci-pan.yaml")

# pci-pan-in-source (pci-pan.yaml) only marks a candidate. A YAML rule can't run a
# checksum, so a match is kept only if a number the rule matched on that line passes Luhn
# and isn't a well-known test card, and only outside test and docs paths.
_PAN_RULE_ID = "pci-pan-in-source"
_PAN_SKIP_CONTEXTS = frozenset({"test", "docs"})
_KNOWN_TEST_PANS = frozenset(
    {
        "4111111111111111",
        "4242424242424242",
        "4012888888881881",
        "4000056655665556",
        "5555555555554444",
        "5105105105105100",
        "2223003122003222",
        "378282246310005",
        "371449635398431",
        "6011111111111117",
        "6011000990139424",
    }
)


def _line_has_real_pan(
    pattern: re.Pattern[str],
    path: Path,
    line_no: int,
    cache: dict[Path, list[str]],
) -> bool:
    """Re-read the matched line and Luhn-check each number the rule pattern matched."""
    if path not in cache:
        try:
            cache[path] = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            cache[path] = []
    lines = cache[path]
    if not 0 < line_no <= len(lines):
        return False
    for match in pattern.finditer(lines[line_no - 1]):
        digits = re.sub(r"[ -]", "", match.group(0))
        if digits not in _KNOWN_TEST_PANS and luhn_valid(digits):
            return True
    return False


async def run_pci_scan(target: str) -> ScanResult:
    """Scan for PCI-DSS cardholder-data exposure (CVV, PANs in logs or source, non-TLS)."""
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

    pan_rule = next((rule for rule in rules if rule.id == _PAN_RULE_ID), None)
    root = Path(target)
    lines_cache: dict[Path, list[str]] = {}
    dropped = 0
    for item in native.findings:
        if item.rule_id == _PAN_RULE_ID and pan_rule is not None:
            path = root if root.is_file() else root / item.file
            if getattr(item, "context", "") in _PAN_SKIP_CONTEXTS or not _line_has_real_pan(
                pan_rule.pattern, path, item.line, lines_cache
            ):
                dropped += 1
                continue
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
                data_classification=item.data_classification,
                confidence=getattr(item, "confidence", ""),
                context=getattr(item, "context", ""),
                fix_guidance=(
                    # argus-ignore[pci-cvv-storage]: advice text shown to users, not card data
                    "Remove or tokenize cardholder data. Never log PANs. Never store CVV/CVC "
                    "after authorization. Send card data only over HTTPS."
                ),
            )
        )

    result.errors.extend(native.errors)
    result.metadata.update(native.metadata)
    result.metadata["rule_pack"] = "pci-dss"
    result.metadata["rules_loaded"] = len(rules)
    result.metadata["pan_candidates_dropped"] = dropped
    return result
