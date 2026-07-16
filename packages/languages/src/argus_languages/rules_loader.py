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
    "java.yaml",
    "php.yaml",
    "terraform.yaml",
    "ansible.yaml",
    "dart.yaml",
    "flutter.yaml",
    "other.yaml",
)


@dataclass
class LoadedRule:
    id: str
    title: str
    severity: Severity
    pattern: re.Pattern[str]
    languages: list[str] | None = None


def _compile_pattern(raw: str, flags: list[str] | None) -> re.Pattern[str]:
    flag_bits = 0
    for f in flags or []:
        if f.lower() == "i":
            flag_bits |= re.IGNORECASE
        elif f.lower() == "m":
            flag_bits |= re.MULTILINE
    return re.compile(raw, flag_bits)


def _parse_yaml_rules(data: Any) -> list[LoadedRule]:
    if not isinstance(data, list):
        return []
    out: list[LoadedRule] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        out.append(
            LoadedRule(
                id=str(item["id"]),
                title=str(item["title"]),
                severity=Severity.normalize(str(item.get("severity", "info"))),
                pattern=_compile_pattern(str(item["pattern"]), item.get("flags")),
                languages=[str(x) for x in item["languages"]] if item.get("languages") else None,
            )
        )
    return out


def load_rules_from_dir(rules_dir: Path | None = None) -> list[LoadedRule]:
    rules: list[LoadedRule] = []
    if rules_dir is not None:
        for path in sorted(rules_dir.glob("*.y*ml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            rules.extend(_parse_yaml_rules(data))
        return rules

    base = resources.files("argus_languages").joinpath("bundled_rules")
    for name in RULE_FILES:
        resource = base.joinpath(name)
        try:
            text = resource.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError, AttributeError):
            continue
        rules.extend(_parse_yaml_rules(yaml.safe_load(text)))
    return rules
