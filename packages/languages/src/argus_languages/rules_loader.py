from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from argus_languages.models import Severity

RULE_FILES = (
    "common.yaml",
    "sql-injection.yaml",
    "database.yaml",
    "ml.yaml",
    "malware.yaml",
    "dependency-sources.yaml",
    "pci-dss.yaml",
    "pii.yaml",
    "auth-jwt.yaml",
    "java.yaml",
    "php.yaml",
    "laravel.yaml",
    "access-control.yaml",
    "composer.yaml",
    "terraform.yaml",
    "ansible.yaml",
    "access-control-web.yaml",
    "dart.yaml",
    "flutter.yaml",
    "other.yaml",
    "github-actions.yaml",
    "exposed-endpoints.yaml",
    "ssti.yaml",
)


@dataclass
class LoadedRule:
    id: str
    title: str
    severity: Severity
    pattern: re.Pattern[str]
    languages: list[str] | None = None
    exclude_languages: list[str] | None = None
    data_classification: str = "unset"
    fix_guidance: str = ""
    confidence: str = "medium"
    # Lower the severity one level for matches in tests, docs, examples and generated files.
    context_sensitive: bool = True
    # Honour `argus-ignore` comments in the scanned code.
    allow_inline_ignore: bool = True
    # Match across source lines while reporting the match's first line.
    multiline: bool = False


CONFIDENCE_LEVELS = ("high", "medium", "low")

# Malware rules look at code that may be hostile: the author of that code must not be
# able to silence them with a comment or by putting the payload under tests/.
_UNTRUSTED_SOURCE_FILES = frozenset({"malware.yaml", "dependency-sources.yaml"})


def _compile_pattern(raw: str, flags: list[str] | None) -> re.Pattern[str]:
    flag_bits = 0
    for f in flags or []:
        if f.lower() == "i":
            flag_bits |= re.IGNORECASE
        elif f.lower() == "m":
            flag_bits |= re.MULTILINE
    return re.compile(raw, flag_bits)


def _parse_yaml_rules(data: Any, source: str = "") -> list[LoadedRule]:
    if not isinstance(data, list):
        return []
    hostile = source in _UNTRUSTED_SOURCE_FILES
    out: list[LoadedRule] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        confidence = str(item.get("confidence", "medium")).lower()
        if confidence not in CONFIDENCE_LEVELS:
            raise ValueError(
                f"Rule {item.get('id')!r}: confidence must be one of {CONFIDENCE_LEVELS}, "
                f"got {confidence!r}"
            )
        out.append(
            LoadedRule(
                id=str(item["id"]),
                title=str(item["title"]),
                severity=Severity.normalize(str(item.get("severity", "info"))),
                pattern=_compile_pattern(str(item["pattern"]), item.get("flags")),
                languages=[str(x) for x in item["languages"]] if item.get("languages") else None,
                exclude_languages=(
                    [str(x) for x in item["exclude_languages"]]
                    if item.get("exclude_languages")
                    else None
                ),
                data_classification=str(item.get("classification", "unset")).lower(),
                fix_guidance=str(item.get("fix_guidance", "")).strip(),
                confidence=confidence,
                context_sensitive=(
                    False if hostile else str(item.get("test_context", "downgrade")) != "keep"
                ),
                allow_inline_ignore=False if hostile else bool(item.get("inline_ignore", True)),
                multiline=bool(item.get("multiline", False)),
            )
        )
    return out


def load_rules_from_dir(rules_dir: Path | None = None) -> list[LoadedRule]:
    rules: list[LoadedRule] = []
    if rules_dir is not None:
        for path in sorted(rules_dir.glob("*.y*ml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            rules.extend(_parse_yaml_rules(data, path.name))
        return rules

    base = resources.files("argus_languages").joinpath("bundled_rules")
    for name in RULE_FILES:
        resource = base.joinpath(name)
        try:
            text = resource.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError, AttributeError):
            continue
        rules.extend(_parse_yaml_rules(yaml.safe_load(text), name))
    return rules


def load_rules_from_files(names: tuple[str, ...]) -> list[LoadedRule]:
    """Load a subset of bundled rule files (e.g. ``('ml.yaml',)`` for ML-only scans)."""
    rules: list[LoadedRule] = []
    base = resources.files("argus_languages").joinpath("bundled_rules")
    for name in names:
        resource = base.joinpath(name)
        try:
            text = resource.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError, AttributeError):
            continue
        rules.extend(_parse_yaml_rules(yaml.safe_load(text), name))
    return rules
