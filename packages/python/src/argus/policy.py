"""Load and apply .argus.yml scan policy."""

from __future__ import annotations

import copy
import fnmatch
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml

POLICY_FILENAME = ".argus.yml"


@dataclass
class Suppression:
    rule_id: str = ""
    path: str = ""
    reason: str = ""
    expires: str | None = None

    def matches(self, finding: dict[str, Any]) -> bool:
        if self.rule_id and finding.get("rule_id") != self.rule_id:
            if self.rule_id not in (finding.get("title", ""), finding.get("tool", "")):
                return False
        if self.path:
            file_path = finding.get("file", "")
            if not fnmatch.fnmatch(file_path, self.path) and not fnmatch.fnmatch(
                Path(file_path).name, self.path
            ):
                return False
        if self.expires:
            try:
                if date.fromisoformat(self.expires) < date.today():
                    return False
            except ValueError:
                pass
        return True


@dataclass
class PolicyConfig:
    fail_on: str = "never"
    min_severity: str = "low"
    exclude_paths: list[str] = field(default_factory=list)
    tools: list[str] | None = None
    semgrep_config: str = "auto"
    baseline: str | None = None
    fail_on_new_only: bool = False
    suppressions: list[Suppression] = field(default_factory=list)
    scans: list[str] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyConfig:
        suppressions = []
        for item in data.get("suppressions", []) or []:
            if isinstance(item, dict):
                suppressions.append(
                    Suppression(
                        rule_id=str(item.get("rule_id", "")),
                        path=str(item.get("path", "")),
                        reason=str(item.get("reason", "")),
                        expires=item.get("expires"),
                    )
                )
        semgrep = data.get("semgrep") or {}
        return cls(
            fail_on=str(data.get("fail_on", "never")),
            min_severity=str(data.get("min_severity", "low")),
            exclude_paths=[str(p) for p in data.get("exclude_paths", []) or []],
            tools=[str(t) for t in data["tools"]] if data.get("tools") else None,
            semgrep_config=str(semgrep.get("config", data.get("semgrep_config", "auto"))),
            baseline=data.get("baseline"),
            fail_on_new_only=bool(data.get("fail_on_new_only", False)),
            suppressions=suppressions,
            scans=[str(s) for s in data["scans"]] if data.get("scans") else None,
        )


def find_policy_file(start: str | Path) -> Path | None:
    """Walk up from start directory looking for .argus.yml."""
    current = Path(start).resolve()
    if current.is_file():
        current = current.parent
    for directory in [current, *current.parents]:
        candidate = directory / POLICY_FILENAME
        if candidate.is_file():
            return candidate
    return None


def load_policy(path: str | Path | None = None, start: str | Path | None = None) -> PolicyConfig:
    """Load policy from explicit path or by discovering .argus.yml."""
    policy_path = Path(path) if path else None
    if policy_path is None and start is not None:
        policy_path = find_policy_file(start)
    if policy_path is None or not policy_path.is_file():
        return PolicyConfig()
    data = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return PolicyConfig()
    return PolicyConfig.from_dict(data)


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def _path_excluded(file_path: str, patterns: list[str]) -> bool:
    if not file_path:
        return False
    name = Path(file_path).name
    for pattern in patterns:
        if fnmatch.fnmatch(file_path, pattern) or fnmatch.fnmatch(name, pattern):
            return True
        if pattern.rstrip("/") in file_path.replace("\\", "/"):
            return True
    return False


def _is_suppressed(finding: dict[str, Any], suppressions: list[Suppression]) -> bool:
    return any(s.matches(finding) for s in suppressions)


def apply_policy(report_dict: dict[str, Any], policy: PolicyConfig) -> dict[str, Any]:
    """Filter findings by policy rules (paths, severity, suppressions)."""
    report = copy.deepcopy(report_dict)
    min_threshold = _SEV_ORDER.get(policy.min_severity, 99)

    for result in report.get("results", []):
        filtered: list[dict[str, Any]] = []
        for finding in result.get("findings", []):
            if _path_excluded(finding.get("file", ""), policy.exclude_paths):
                continue
            if _is_suppressed(finding, policy.suppressions):
                continue
            sev = _SEV_ORDER.get(finding.get("severity", "unknown"), 99)
            if sev > min_threshold:
                continue
            filtered.append(finding)
        result["findings"] = filtered

    return report


def merge_cli_policy(
    policy: PolicyConfig,
    *,
    fail_on: str | None = None,
    min_severity: str | None = None,
    tools: list[str] | None = None,
    semgrep_config: str | None = None,
) -> PolicyConfig:
    """CLI flags override policy file when explicitly set."""
    merged = copy.copy(policy)
    if fail_on is not None and fail_on != "never":
        merged.fail_on = fail_on
    if min_severity is not None and min_severity != "low":
        merged.min_severity = min_severity
    if tools:
        merged.tools = tools
    if semgrep_config is not None and semgrep_config != "auto":
        merged.semgrep_config = semgrep_config
    return merged
