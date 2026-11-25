"""`argus scan pii`: personal data hardcoded or mishandled in code, config and fixtures (#52).

Three parts:

- ``pii.yaml``: PII written to logs, prints and error messages (also part of every code scan)
- ``pii-hardcoded.yaml``: real-looking emails, phone numbers, SSNs, UK NI numbers, names and
  street addresses as literal values (only in this scan: sample data is everywhere)
- ``pci-pan.yaml``: card numbers, kept only when they pass the Luhn check (shared with
  ``argus scan pci``)

The rule engine covers source files. Data files where real customer data tends to end up
(JSON / YAML / CSV fixtures, .env, SQL dumps, .properties, XML) are checked line by line
with the same rules.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from argus_languages.noise import path_context
from argus_languages.rules_loader import load_rules_from_files
from argus_languages.scanner import scan_path as _scan_path

from argus.models import Finding, ScanResult, ScanType, Severity
from argus.tools.pci import _KNOWN_TEST_PANS, _PAN_RULE_ID, _SEV_MAP, _line_has_real_pan

logger = logging.getLogger(__name__)

TOOL = "argus-pii"
PII_RULE_FILES = ("pii.yaml", "pii-hardcoded.yaml", "pci-pan.yaml")
_DATA_SUFFIXES = frozenset(
    {".json", ".yaml", ".yml", ".csv", ".tsv", ".sql", ".xml", ".properties", ".ini", ".toml"}
)
_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        ".next",
        "target",
        "vendor",
        "coverage",
    }
)
_LOCKFILES = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "composer.lock",
        "poetry.lock",
        "Pipfile.lock",
        "uv.lock",
        "Cargo.lock",
    }
)
_MAX_FILE = 2 * 1024 * 1024
# In tests and docs, sample people are the norm: only government ID numbers are reported there.
_REPORT_IN_TESTS = frozenset({"pii-hardcoded-ssn", "pii-hardcoded-uk-nino"})
_DOWNGRADE = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFO,
}


def _is_data_file(path: Path) -> bool:
    name = path.name
    if name in _LOCKFILES:
        return False
    return path.suffix.lower() in _DATA_SUFFIXES or name == ".env" or name.startswith(".env.")


def _data_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if _is_data_file(root) else []
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if _is_data_file(path):
                out.append(path)
    return out


def _finding(
    rule_id: str,
    title: str,
    severity: Severity,
    file: str,
    line: int,
    *,
    confidence: str,
    context: str,
    fix: str,
    description: str,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        scan_type=ScanType.SAST,
        tool=TOOL,
        file=file,
        line=line,
        rule_id=rule_id,
        description=description,
        fix_guidance=fix,
        data_classification="pii" if rule_id != _PAN_RULE_ID else "pci",
        confidence=confidence,
        context=context,
        cwe="CWE-359",
    )


def _skip_in_context(rule_id: str, context: str) -> bool:
    return bool(context) and rule_id.startswith("pii-hardcoded") and rule_id not in _REPORT_IN_TESTS


async def run_pii_scan(target: str) -> ScanResult:
    """Scan for personal data in code, config and fixtures."""
    result = ScanResult(tool=TOOL, scan_type=ScanType.SAST, target=target)
    try:
        rules = load_rules_from_files(PII_RULE_FILES)
    except Exception as exc:  # pragma: no cover - broken install
        result.errors.append(f"argus-pii error: {exc}")
        return result
    if not any(r.id.startswith("pii-hardcoded") for r in rules):
        result.errors.append(
            "argus-pii: the installed argus-languages has no pii-hardcoded.yaml; upgrade it to "
            "check for hardcoded personal data."
        )
    root = Path(target)
    base = root if root.is_dir() else root.parent
    pan_rule = next((r for r in rules if r.id == _PAN_RULE_ID), None)
    cache: dict[Path, list[str]] = {}
    seen: set[tuple[str, int, str]] = set()
    dropped = 0
    skipped = 0

    def keep_pan(path: Path, line: int, context: str) -> bool:
        return (
            pan_rule is not None
            and context not in {"test", "docs"}
            and _line_has_real_pan(pan_rule.pattern, path, line, cache)
        )

    # 1. Source files through the rule engine.
    try:
        native = _scan_path(target, rules=rules)
    except Exception as exc:
        logger.exception("argus-pii scan failed")
        result.errors.append(f"argus-pii error: {exc}")
        return result
    for item in native.findings:
        context = getattr(item, "context", "")
        if item.rule_id == _PAN_RULE_ID and not keep_pan(
            root if root.is_file() else root / item.file, item.line, context
        ):
            dropped += 1
            continue
        seen.add((item.file, item.line, item.rule_id))
        if _skip_in_context(item.rule_id, context):
            skipped += 1
            continue
        result.findings.append(
            _finding(
                item.rule_id,
                item.title,
                _SEV_MAP.get(item.severity, Severity.INFO),
                item.file,
                item.line,
                confidence=getattr(item, "confidence", ""),
                context=context,
                fix=getattr(item, "fix_guidance", "") or "",
                description=item.description or "",
            )
        )

    # 2. Data files (fixtures, dumps, config) with the same rules.
    data_rules = [r for r in rules if r.id.startswith("pii-hardcoded") or r.id == _PAN_RULE_ID]
    for path in _data_files(root):
        rel = path.relative_to(base).as_posix() if path != base else path.name
        try:
            if path.stat().st_size > _MAX_FILE:
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        context = path_context(rel) or ""
        for number, text in enumerate(lines, start=1):
            for rule in data_rules:
                if not rule.pattern.search(text) or (rel, number, rule.id) in seen:
                    continue
                if rule.id == _PAN_RULE_ID:
                    cache[path] = lines
                    if not keep_pan(path, number, context):
                        dropped += 1
                        continue
                seen.add((rel, number, rule.id))
                if _skip_in_context(rule.id, context):
                    skipped += 1
                    continue
                severity = _SEV_MAP.get(rule.severity, Severity.INFO)
                if context:
                    severity = _DOWNGRADE.get(severity, severity)
                result.findings.append(
                    _finding(
                        rule.id,
                        rule.title,
                        severity,
                        rel,
                        number,
                        confidence=rule.confidence,
                        context=context,
                        fix=rule.fix_guidance,
                        description="Found in a data file.",
                    )
                )

    result.errors.extend(native.errors)
    result.metadata.update(native.metadata)
    result.metadata.update(
        {
            "rule_pack": "pii",
            "rules_loaded": len(rules),
            "pan_candidates_dropped": dropped,
            "skipped_in_tests_and_docs": skipped,
            "known_test_cards_ignored": len(_KNOWN_TEST_PANS),
        }
    )
    return result
