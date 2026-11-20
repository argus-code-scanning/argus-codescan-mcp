"""Build the Argus pull-request comment from SARIF scan output.

CI already writes SARIF for GitHub Code Scanning, so the comment is built
from those files instead of running the scanners again. The comment holds a
severity summary per tool, links to the CI run and cloud dashboard, and the
highest-priority fix suggestions from :func:`build_fix_plan`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from argus.models import Severity
from argus.remediation.explain import _GUIDANCE as SCAN_TYPE_GUIDANCE
from argus.remediation.plan import build_fix_plan

# Hidden marker used to find and update the bot's previous comment.
COMMENT_MARKER = "<!-- argus-pr-comment -->"
DEFAULT_MAX_SUGGESTIONS = 5

# GitHub rejects comment bodies over 65536 characters.
_MAX_COMMENT_CHARS = 60000
_MAX_LOCATIONS = 3
_MAX_GUIDANCE_CHARS = 400

_TABLE_SEVERITIES = ("critical", "high", "medium", "low")
_SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
    "unknown": "⚪",
}
_VALID_SEVERITIES = {severity.value for severity in Severity}
_MENTION_RE = re.compile(r"@(?=\w)")


def _inline(text: str, limit: int = 200) -> str:
    """Flatten scanner text for one Markdown line.

    Finding text can echo code from the pull request, so HTML is escaped and
    ``@`` mentions are broken to stop the bot from pinging users.
    """
    flat = " ".join(str(text).split())
    if len(flat) > limit:
        flat = flat[: limit - 1].rstrip() + "…"
    flat = flat.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    flat = flat.replace("|", "\\|")
    return _MENTION_RE.sub("@\u200b", flat)


def _code(text: str, limit: int = 120) -> str:
    """Wrap ``text`` in a code span that cannot be closed early."""
    flat = " ".join(str(text).split())
    if len(flat) > limit:
        flat = flat[: limit - 1] + "…"
    flat = flat.replace("`", "'").replace("|", "\\|")
    return f"`{flat}`" if flat else ""


def report_from_sarif(sarif: dict[str, Any]) -> dict[str, Any]:
    """Rebuild an AggregatedReport-style dict from Argus SARIF output.

    Only the fields the comment needs are restored. Rule help text equal to
    the rule description is a fallback written by the SARIF formatter, so it
    is not treated as fix guidance.
    """
    results: dict[str, dict[str, Any]] = {}
    target = ""
    for run in sarif.get("runs", []):
        target = target or run.get("properties", {}).get("target", "")
        rules = {
            rule.get("id", ""): rule
            for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for entry in run.get("results", []):
            props = entry.get("properties", {})
            rule_key = entry.get("ruleId", "")
            rule = rules.get(rule_key, {})
            tool = props.get("tool") or rule_key.split("/", 1)[0] or "argus"
            severity = str(props.get("severity", "unknown")).lower()
            if severity not in _VALID_SEVERITIES:
                severity = Severity.UNKNOWN.value

            description = rule.get("fullDescription", {}).get("text", "")
            guidance = rule.get("help", {}).get("text", "")
            if guidance == description:
                guidance = ""

            file = ""
            line = 0
            locations = entry.get("locations") or []
            if locations:
                physical = locations[0].get("physicalLocation", {})
                file = physical.get("artifactLocation", {}).get("uri", "")
                line = int(physical.get("region", {}).get("startLine", 0) or 0)

            rule_id = rule_key.split("/", 1)[1] if "/" in rule_key else rule_key
            scan_type = props.get("scan_type", "")
            result = results.setdefault(
                tool,
                {"tool": tool, "scan_type": scan_type, "findings": [], "errors": []},
            )
            result["findings"].append(
                {
                    "title": rule.get("shortDescription", {}).get("text", "")
                    or entry.get("message", {}).get("text", "Security finding"),
                    "severity": severity,
                    "scan_type": scan_type,
                    "tool": tool,
                    "file": file,
                    "line": line,
                    "column": 0,
                    "rule_id": rule_id,
                    "fix_guidance": guidance,
                    "references": [],
                }
            )
    return {"target": target, "results": list(results.values())}


def load_sarif_reports(paths: list[Path]) -> tuple[dict[str, Any], list[str]]:
    """Merge SARIF files into one report. Missing files are reported, not fatal."""
    merged: dict[str, Any] = {"target": "", "results": []}
    missing: list[str] = []
    for path in paths:
        if not path.is_file():
            missing.append(str(path))
            continue
        report = report_from_sarif(json.loads(path.read_text(encoding="utf-8")))
        merged["target"] = merged["target"] or report["target"]
        merged["results"].extend(report["results"])
    return merged, missing


def _severity_counts(report: dict[str, Any]) -> dict[str, dict[str, int]]:
    """Count findings per tool and severity, keeping first-seen tool order."""
    counts: dict[str, dict[str, int]] = {}
    for result in report.get("results", []):
        for finding in result.get("findings", []):
            tool_counts = counts.setdefault(
                finding.get("tool") or result.get("tool", "argus"),
                {severity.value: 0 for severity in Severity},
            )
            tool_counts[finding.get("severity", "unknown")] += 1
    return counts


def _summary_table(counts: dict[str, dict[str, int]]) -> list[str]:
    header = ["Tool", *(s.capitalize() for s in _TABLE_SEVERITIES), "Other", "Total"]
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    totals = {severity.value: 0 for severity in Severity}

    def _row(label: str, row: dict[str, int]) -> str:
        other = row["info"] + row["unknown"]
        cells = [str(row[s]) for s in _TABLE_SEVERITIES]
        total = sum(row.values())
        return f"| {label} | " + " | ".join([*cells, str(other), str(total)]) + " |"

    for tool, row in counts.items():
        lines.append(_row(_inline(tool, 60), row))
        for severity, value in row.items():
            totals[severity] += value
    if len(counts) > 1:
        lines.append(_row("**Total**", totals))
    return lines


def _format_location(location: dict[str, Any]) -> str:
    file = location.get("file", "")
    if not file:
        return ""
    line = location.get("line", 0)
    return _code(f"{file}:{line}" if line else file)


def _suggestion_lines(index: int, group: dict[str, Any]) -> list[str]:
    severity = group["severity"]
    icon = _SEVERITY_ICONS.get(severity, "⚪")
    count = group["finding_count"]
    heading = (
        f"{index}. {icon} **{severity.upper()}** — {_inline(group['title'] or group['rule_id'])}"
    )
    meta = [_inline(group["tool"], 60)]
    if group["rule_id"]:
        meta.append(_code(group["rule_id"], 80))
    meta.append(f"{count} occurrence{'s' if count != 1 else ''}")
    lines = [heading, f"   - {' · '.join(meta)}"]

    locations = [loc for loc in map(_format_location, group["locations"]) if loc]
    if locations:
        shown = ", ".join(locations[:_MAX_LOCATIONS])
        extra = len(locations) - _MAX_LOCATIONS
        if extra > 0:
            shown += f" and {extra} more"
        lines.append(f"   - Where: {shown}")

    guidance = group["fix_guidance"][0] if group["fix_guidance"] else ""
    guidance = guidance or SCAN_TYPE_GUIDANCE.get(
        group["scan_type"], "Review the flagged code and apply the rule's recommended change."
    )
    lines.append(f"   - Fix: {_inline(guidance, _MAX_GUIDANCE_CHARS)}")
    return lines


def _ai_prompt(groups: list[dict[str, Any]]) -> list[str]:
    """Plain-text task list that can be pasted into an AI coding assistant."""
    body = [
        "Fix these security findings reported by Argus on this pull request.",
        "Keep each change minimal and add a regression test where practical.",
        "",
    ]
    for index, group in enumerate(groups, 1):
        where = ", ".join(
            f"{loc['file']}:{loc['line']}" if loc.get("line") else loc["file"]
            for loc in group["locations"][:_MAX_LOCATIONS]
            if loc.get("file")
        )
        title = " ".join((group["title"] or group["rule_id"]).split())
        rule = f" ({group['rule_id']})" if group["rule_id"] else ""
        body.append(f"{index}. [{group['severity']}] {title}{rule} in {where or 'repository'}")
    # Four backticks so a stray ``` in finding text cannot end the block.
    text = "\n".join(body).replace("````", "'''")
    return [
        "<details>",
        "<summary>Prompt for an AI assistant</summary>",
        "",
        "````text",
        _MENTION_RE.sub("@\u200b", text),
        "````",
        "",
        "</details>",
    ]


def build_pr_comment(
    report: dict[str, Any],
    *,
    scope_mode: str | None = None,
    changed_count: int | None = None,
    run_url: str | None = None,
    dashboard_url: str | None = None,
    missing_reports: list[str] | None = None,
    max_suggestions: int = DEFAULT_MAX_SUGGESTIONS,
) -> str:
    """Render the Markdown body for the Argus pull-request comment."""
    counts = _severity_counts(report)
    total = sum(sum(row.values()) for row in counts.values())
    lines = [COMMENT_MARKER, "## 🛡️ Argus security scan", ""]

    if scope_mode == "changed" and changed_count is not None:
        lines.append(f"Scanned **{changed_count}** changed file(s) with SAST and secrets.")
    elif scope_mode == "full":
        detail = f" ({changed_count} files changed)" if changed_count is not None else ""
        lines.append(f"Large diff{detail}, so the full repository was scanned.")
    elif scope_mode == "empty":
        lines.append("No scannable files changed in this pull request (only deletions).")
    lines.append("")

    if missing_reports and scope_mode != "empty":
        names = ", ".join(_code(Path(name).name) for name in missing_reports)
        lines += [f"⚠️ No results from {names}. Check the workflow logs.", ""]

    if total == 0:
        lines += ["✅ **No findings.**", ""]
    else:
        lines += [f"**{total} finding(s)**", "", *_summary_table(counts), ""]

    links = []
    if dashboard_url:
        links.append(f"[Cloud dashboard run]({dashboard_url})")
    if run_url:
        links.append(f"[Workflow run and SARIF artifact]({run_url})")
    if links:
        lines += [" · ".join(links), ""]

    if total:
        groups = build_fix_plan(report)["groups"][: max(max_suggestions, 0)]
        if groups:
            lines += [f"### Top {len(groups)} fix suggestion(s)", ""]
            for index, group in enumerate(groups, 1):
                lines += _suggestion_lines(index, group)
            lines += ["", *_ai_prompt(groups), ""]

    lines.append("<sub>Updated on every push by the Argus scan workflow.</sub>")
    body = "\n".join(lines) + "\n"
    if len(body) > _MAX_COMMENT_CHARS:
        body = body[:_MAX_COMMENT_CHARS] + "\n\n…comment truncated. See the workflow run.\n"
    return body
