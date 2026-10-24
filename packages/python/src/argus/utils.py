"""Shared utilities for running external security tools."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from argus.models import ScanResult, ScanType, Severity

logger = logging.getLogger(__name__)

# Directories skipped when walking project trees for language/SCA detection.
SKIP_SCAN_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        "dist",
        "build",
        ".next",
        "coverage",
        "vendor",
        "__pycache__",
        "target",
        "bin",
        "obj",
        ".venv",
        "venv",
        ".terraform",
        ".idea",
        ".vscode",
        "Pods",
        "DerivedData",
        ".dart_tool",
        ".pub-cache",
        ".gradle",
    }
)


def find_scan_files(root: Path, *patterns: str) -> list[Path]:
    """Find files under ``root`` matching globs, skipping heavy directories."""
    if not patterns:
        return []
    if root.is_file():
        return [root] if any(root.match(pattern) for pattern in patterns) else []

    found: list[Path] = []

    def walk(dir_path: Path) -> None:
        try:
            entries = list(dir_path.iterdir())
        except OSError:
            return
        for entry in entries:
            # Keep recursive scanner discovery inside the requested project tree.
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name in SKIP_SCAN_DIRS:
                    continue
                walk(entry)
            elif any(entry.match(pattern) for pattern in patterns):
                found.append(entry)

    if root.is_dir():
        walk(root)
    return found


def collect_scan_results(
    results: list[ScanResult | BaseException],
    *,
    label: str = "Scan tool",
) -> list[ScanResult]:
    """Filter asyncio.gather(..., return_exceptions=True) results for mypy-safe use."""
    final: list[ScanResult] = []
    for item in results:
        if isinstance(item, ScanResult):
            final.append(item)
        elif isinstance(item, BaseException):
            logger.exception("%s raised an exception: %s", label, item)
    return final


def refresh_report_summary(report: dict[str, Any]) -> None:
    """Recompute report and per-tool counts after a finding filter."""
    by_severity = {severity.value: 0 for severity in Severity}
    by_scan_type = {scan_type.value: 0 for scan_type in ScanType}
    by_tool: dict[str, int] = {}
    total = 0

    for result in report.get("results", []):
        result_counts = {severity.value: 0 for severity in Severity}
        findings = result.get("findings", [])
        for finding in findings:
            severity = finding.get("severity", Severity.UNKNOWN.value)
            if severity not in result_counts:
                severity = Severity.UNKNOWN.value
            result_counts[severity] += 1
            by_severity[severity] += 1

            scan_type = finding.get("scan_type", result.get("scan_type", ""))
            if scan_type not in by_scan_type:
                by_scan_type[scan_type] = 0
            by_scan_type[scan_type] += 1

            tool = finding.get("tool", result.get("tool", ""))
            by_tool[tool] = by_tool.get(tool, 0) + 1
            total += 1

        result["summary"] = {**result_counts, "total": len(findings)}

    old_summary = report.get("summary", {})
    report["summary"] = {
        "total_findings": total,
        "by_severity": by_severity,
        "by_scan_type": by_scan_type,
        "by_tool": by_tool,
        "tools_run": [result.get("tool", "") for result in report.get("results", [])],
        "tools_unavailable": [
            result.get("tool", "")
            for result in report.get("results", [])
            if not result.get("tool_available", True)
        ],
    }
    # Preserve summary metadata this helper does not own.
    for key, value in old_summary.items():
        if key not in report["summary"]:
            report["summary"][key] = value


def is_tool_available(name: str) -> bool:
    """Check if a CLI tool is available on PATH."""
    return shutil.which(name) is not None


async def run_command(
    args: list[str],
    cwd: str | None = None,
    timeout: int = 300,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    """Run a subprocess command asynchronously and return (returncode, stdout, stderr)."""
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)

    proc: asyncio.subprocess.Process | None = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=merged_env,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return (
            proc.returncode or 0,
            stdout_bytes.decode(errors="replace"),
            stderr_bytes.decode(errors="replace"),
        )
    except asyncio.TimeoutError:
        logger.warning("Command timed out after %ds: %s", timeout, " ".join(args))
        if proc is not None:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Tool not found: {args[0]}"
    except Exception as exc:
        logger.exception("Unexpected error running command %s", args)
        return -1, "", str(exc)


def parse_json_output(output: str) -> Any:
    """Safely parse JSON output, returning None on failure."""
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        # raw_decode handles nested containers and delimiter characters inside strings.
        decoder = json.JSONDecoder()
        for start, char in enumerate(output):
            if char not in "[{":
                continue
            try:
                value, _ = decoder.raw_decode(output, start)
            except json.JSONDecodeError:
                continue
            if isinstance(value, (dict, list)):
                return value
        return None


def resolve_target(target: str) -> Path:
    """Resolve a target path, expanding ~ and making absolute."""
    return Path(target).expanduser().resolve()


def format_markdown_report(report_dict: dict[str, Any]) -> str:
    """Format an aggregated report dict as Markdown."""
    lines: list[str] = []
    summary = report_dict.get("summary", {})

    lines.append(f"# Security Scan Report — `{report_dict.get('target', 'unknown')}`\n")
    lines.append("## Summary\n")
    lines.append(f"**Total findings:** {summary.get('total_findings', 0)}\n")

    by_sev = summary.get("by_severity", {})
    sev_order = ["critical", "high", "medium", "low", "info", "unknown"]
    sev_emojis = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
        "unknown": "⬜",
    }
    lines.append("\n| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in sev_order:
        count = by_sev.get(sev, 0)
        if count:
            lines.append(f"| {sev_emojis.get(sev, '')} {sev.capitalize()} | {count} |")

    lines.append("\n## Results by Tool\n")
    for result in report_dict.get("results", []):
        tool = result.get("tool", "unknown")
        scan_type = result.get("scan_type", "")
        available = result.get("tool_available", True)

        if not available:
            lines.append(f"### {tool} ({scan_type}) — ⚠️ Not installed\n")
            continue

        result_summary = result.get("summary", {})
        total = result_summary.get("total", 0)
        lines.append(f"### {tool} ({scan_type}) — {total} finding(s)\n")

        findings = result.get("findings", [])
        if findings:
            lines.append("| Severity | Title | File | Line |")
            lines.append("|----------|-------|------|------|")
            for f in findings[:50]:  # Cap at 50 per tool for readability
                sev = f.get("severity", "unknown")
                emoji = sev_emojis.get(sev, "")
                title = f.get("title", "")[:60]
                file_ = Path(f.get("file", "")).name
                line = f.get("line", "")
                lines.append(f"| {emoji} {sev} | {title} | {file_} | {line} |")
            if len(findings) > 50:
                lines.append(f"\n_...and {len(findings) - 50} more findings_\n")

        if result.get("errors"):
            lines.append("\n**Errors:**")
            for err in result["errors"][:5]:
                lines.append(f"- {err}")

        lines.append("")

    return "\n".join(lines)


def get_python_executable() -> str:
    """Return the current Python executable path."""
    return sys.executable
