"""Batch fixes with one diff preview and one confirmation (#40).

1. Preview (``apply=False``): every automatically fixable finding is fixed in memory (GitHub
   Actions rules) or on a temporary sibling copy of its file (ESLint / Semgrep, so the project's
   own lint config applies). Nothing in the project changes. The result is one unified diff
   and a ``confirm_token``: a hash of the diff and of every file it touches.
2. Apply (``apply=True`` + ``confirm_token``): the plan is computed again; if the files or the
   fixes changed since the preview the token no longer matches and nothing is written.
   Otherwise exactly the previewed changes are written.

Several findings in one file are fixed from the bottom up, so earlier fixes can't shift the
lines later ones point at.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import secrets
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from argus.remediation import github_actions
from argus.tools.fix import (
    GUIDANCE_ONLY_SCAN_TYPES,
    _autofix_available,
    _run_eslint_fix,
    _run_semgrep_autofix,
)

MAX_FINDINGS = 50


@dataclass(frozen=True)
class FixItem:
    file: str
    tool: str
    scan_type: str = "sast"
    rule_id: str = ""
    line: int = 0

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FixItem:
        return cls(
            file=str(d.get("file", "")),
            tool=str(d.get("tool", "")),
            scan_type=str(d.get("scan_type", "sast") or "sast"),
            rule_id=str(d.get("rule_id", "") or ""),
            line=int(d.get("line", 0) or 0),
        )


@dataclass
class Plan:
    results: list[dict[str, Any]] = field(default_factory=list)
    new_text: dict[str, str] = field(default_factory=dict)  # relative path -> fixed content
    before_hash: dict[str, str] = field(default_factory=dict)
    diff: str = ""

    @property
    def token(self) -> str:
        payload = json.dumps({"files": self.before_hash, "diff": self.diff}, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()[:32]


def items_from_report(report: dict[str, Any]) -> list[FixItem]:
    """Every finding in an Argus JSON report (the AggregatedReport format)."""
    items: list[FixItem] = []
    for result in report.get("results", []):
        for f in result.get("findings", []):
            items.append(
                FixItem.from_dict(
                    {
                        "file": f.get("file"),
                        "tool": f.get("tool") or result.get("tool", ""),
                        "scan_type": f.get("scan_type") or result.get("scan_type", "sast"),
                        "rule_id": f.get("rule_id"),
                        "line": f.get("line"),
                    }
                )
            )
    return items


def _fixable(item: FixItem) -> bool:
    return item.scan_type not in GUIDANCE_ONLY_SCAN_TYPES and (
        github_actions.handles(item.rule_id)
        or _autofix_available(item.tool, item.scan_type, item.rule_id)
    )


def _resolve(target: Path, file: str) -> tuple[Path, str] | None:
    path = Path(file)
    path = (path if path.is_absolute() else target / path).resolve()
    try:
        rel = path.relative_to(target)
    except ValueError:
        return None
    return path, rel.as_posix()


async def _fix_with_tool(
    path: Path, text: str, item: FixItem, semgrep_config: str, timeout: int
) -> tuple[bool, str, str]:
    """Run ESLint/Semgrep fix on a temporary copy next to the file; return the fixed text."""
    tmp = path.with_name(f".argus-fix-{secrets.token_hex(4)}-{path.name}")
    try:
        tmp.write_text(text, encoding="utf-8")
        tool = item.tool.lower().replace("_", "-")
        if tool.startswith("eslint"):
            ok, message = await _run_eslint_fix(str(tmp), timeout)
        else:
            ok, message = await _run_semgrep_autofix(str(tmp), semgrep_config, timeout)
        return ok, message, tmp.read_text(encoding="utf-8") if ok else text
    finally:
        tmp.unlink(missing_ok=True)


async def build_plan(
    target: str,
    items: list[FixItem],
    *,
    semgrep_config: str = "auto",
    timeout: int = 120,
) -> Plan:
    root = Path(target).resolve()
    if root.is_file():
        root = root.parent
    plan = Plan()
    by_file: dict[str, list[FixItem]] = {}
    seen: set[FixItem] = set()

    for item in items[: MAX_FINDINGS * 4]:
        if item in seen:
            continue
        seen.add(item)
        entry = {"file": item.file, "line": item.line, "rule_id": item.rule_id, "tool": item.tool}
        if not _fixable(item):
            continue  # guidance-only findings are simply not part of a batch
        resolved = _resolve(root, item.file)
        if resolved is None:
            plan.results.append(
                {**entry, "status": "refused", "message": "Outside the scan target."}
            )
            continue
        path, rel = resolved
        if not path.is_file():
            plan.results.append({**entry, "status": "skipped", "message": "File not found."})
            continue
        by_file.setdefault(rel, []).append(item)

    count = sum(len(v) for v in by_file.values())
    if count > MAX_FINDINGS:
        plan.results.append(
            {
                "status": "limited",
                "message": f"{count} fixable findings; only the first {MAX_FINDINGS} are included.",
            }
        )

    budget = MAX_FINDINGS
    diffs: list[str] = []
    for rel in sorted(by_file):
        path = root / rel
        original = path.read_text(encoding="utf-8")
        plan.before_hash[rel] = hashlib.sha256(original.encode()).hexdigest()
        text = original
        # Bottom-up: a fix that adds lines can't move the lines of fixes above it.
        for item in sorted(by_file[rel], key=lambda i: i.line, reverse=True):
            if budget <= 0:
                break
            budget -= 1
            entry = {"file": rel, "line": item.line, "rule_id": item.rule_id, "tool": item.tool}
            if github_actions.handles(item.rule_id):
                outcome = await github_actions.fix_github_actions(text, item.rule_id, item.line)
                ok, message, fixed = (
                    outcome.ok,
                    outcome.message,
                    outcome.text if outcome.ok else text,
                )
            else:
                ok, message, fixed = await _fix_with_tool(path, text, item, semgrep_config, timeout)
            changed = ok and fixed != text
            plan.results.append(
                {
                    **entry,
                    "status": "fixed" if changed else ("no-change" if ok else "failed"),
                    "message": message,
                }
            )
            if changed:
                text = fixed
        if text != original:
            plan.new_text[rel] = text
            diffs.append(
                "".join(
                    difflib.unified_diff(
                        original.splitlines(keepends=True),
                        text.splitlines(keepends=True),
                        fromfile=f"a/{rel}",
                        tofile=f"b/{rel}",
                    )
                )
            )
    plan.diff = "".join(diffs)
    return plan


async def batch_fix(
    target: str,
    items: list[FixItem],
    *,
    apply: bool = False,
    confirm_token: str = "",
    semgrep_config: str = "auto",
    timeout: int = 120,
) -> dict[str, Any]:
    plan = await build_plan(target, items, semgrep_config=semgrep_config, timeout=timeout)
    summary = {
        "fixable": sum(1 for r in plan.results if r.get("status") == "fixed"),
        "files": sorted(plan.new_text),
        "results": plan.results,
        "diff": plan.diff,
        "confirm_token": plan.token if plan.new_text else "",
        "applied": False,
    }
    if not apply:
        summary["message"] = (
            "Preview only: nothing was changed. Show the diff to the user; to write it, call "
            "apply_fixes again with apply=true and this confirm_token."
            if plan.new_text
            else "No automated fixes are available for these findings."
        )
        return summary
    if not plan.new_text:
        summary["message"] = "Nothing to apply."
        return summary
    if not confirm_token or confirm_token != plan.token:
        summary["message"] = (
            "Not applied: confirm_token is missing or doesn't match. The files or the fixes "
            "changed since the preview; preview again and confirm the new diff."
        )
        return summary
    root = Path(target).resolve()
    root = root.parent if root.is_file() else root
    for rel, text in plan.new_text.items():
        path = root / rel
        tmp = path.with_name(f".argus-write-{secrets.token_hex(4)}-{path.name}")
        tmp.write_text(text, encoding="utf-8")
        shutil.copymode(path, tmp)  # keep permissions (executable scripts stay executable)
        os.replace(tmp, path)  # atomic per file
    summary["applied"] = True
    summary["message"] = (
        f"Applied {summary['fixable']} fix(es) in {len(plan.new_text)} file(s). Re-scan to verify."
    )
    return summary
