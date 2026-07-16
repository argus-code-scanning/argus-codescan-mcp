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

from argus.models import ScanResult

logger = logging.getLogger(__name__)


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
        # Try to find the first JSON object/array in mixed output
        for start_char, end_char in (("{", "}"), ("[", "]")):
            start = output.find(start_char)
            if start != -1:
                # Find matching end
                depth = 0
                for i, ch in enumerate(output[start:], start):
                    if ch == start_char:
                        depth += 1
                    elif ch == end_char:
                        depth -= 1
                        if depth == 0:
                            try:
                                return json.loads(output[start : i + 1])
                            except json.JSONDecodeError:
                                break
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
