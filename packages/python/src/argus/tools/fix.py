"""Apply security fixes only when explicitly requested.

Scans never modify files. Call ``apply_finding_fix`` with ``apply=True`` only
after the user (or AI acting on their behalf) asks to fix a specific finding.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from argus.utils import is_tool_available, run_command

logger = logging.getLogger(__name__)

# Tools that support a safe, file-scoped automated fix command.
AUTOFIX_TOOLS = frozenset({"eslint", "eslint-security", "semgrep"})

# Findings that must never be auto-modified — guidance only.
GUIDANCE_ONLY_SCAN_TYPES = frozenset({"secrets", "sca", "dast", "container"})


def _autofix_available(tool: str, scan_type: str) -> bool:
    if scan_type in GUIDANCE_ONLY_SCAN_TYPES:
        return False
    normalized = tool.lower().replace("_", "-")
    if normalized.startswith("eslint"):
        return is_tool_available("eslint") or is_tool_available("npx")
    if normalized == "semgrep":
        return is_tool_available("semgrep")
    return normalized in AUTOFIX_TOOLS and is_tool_available(normalized)


async def _run_eslint_fix(file_path: str, timeout: int) -> tuple[bool, str]:
    path = Path(file_path)
    eslint_cmd = "eslint"
    if not is_tool_available("eslint"):
        if is_tool_available("npx"):
            eslint_cmd = "npx"
        else:
            return False, "eslint is not installed"

    cmd: list[str]
    if eslint_cmd == "npx":
        cmd = [
            "npx",
            "--yes",
            "eslint",
            "--fix",
            "--plugin",
            "security",
            str(path),
        ]
    else:
        cmd = [
            "eslint",
            "--fix",
            "--plugin",
            "security",
            str(path),
        ]

    code, stdout, stderr = await run_command(cmd, cwd=path.parent, timeout=timeout)
    output = (stdout + stderr).strip()
    if code not in (0, 1):
        return False, output or f"eslint --fix exited with code {code}"
    return True, output or "Applied ESLint --fix to the file."


async def _run_semgrep_autofix(file_path: str, config: str, timeout: int) -> tuple[bool, str]:
    if not is_tool_available("semgrep"):
        return False, "semgrep is not installed. Install with: pip install semgrep"

    path = Path(file_path)
    cmd = [
        "semgrep",
        "scan",
        "--autofix",
        "--config",
        config,
        "--timeout",
        str(timeout),
        str(path),
    ]
    code, stdout, stderr = await run_command(cmd, timeout=timeout + 30)
    output = (stdout + stderr).strip()
    if code not in (0, 1):
        return False, output or f"semgrep --autofix exited with code {code}"
    return True, output or "Applied Semgrep autofix to the file."


async def apply_finding_fix(
    *,
    target: str,
    file: str,
    tool: str,
    scan_type: str = "sast",
    rule_id: str = "",
    line: int = 0,
    fix_guidance: str = "",
    apply: bool = False,
    semgrep_config: str = "auto",
    timeout: int = 120,
) -> dict[str, Any]:
    """Return fix guidance, or apply an automated fix when ``apply=True``."""
    file_path = Path(file)
    if not file_path.is_absolute():
        file_path = Path(target) / file
    resolved_file = str(file_path.resolve())

    autofix = _autofix_available(tool, scan_type)
    normalized_tool = tool.lower().replace("_", "-")

    result: dict[str, Any] = {
        "file": resolved_file,
        "tool": tool,
        "rule_id": rule_id,
        "line": line,
        "fix_guidance": fix_guidance,
        "autofix_available": autofix,
        "applied": False,
        "message": "",
    }

    if not apply:
        if fix_guidance:
            result["message"] = fix_guidance
        elif autofix:
            result["message"] = (
                "Automated fix is available for this finding. "
                "Call apply_fix again with apply=true after the user confirms."
            )
        else:
            result["message"] = (
                "No automated fix is available for this finding. "
                "Review the description and fix_guidance manually."
            )
        return result

    if scan_type in GUIDANCE_ONLY_SCAN_TYPES:
        result["message"] = (
            f"{scan_type.upper()} findings cannot be auto-fixed. "
            "Follow fix_guidance manually (e.g. rotate secrets, upgrade dependencies)."
        )
        return result

    if not autofix:
        result["message"] = (
            "Automated fix is not supported for this tool. "
            "Use fix_guidance to apply a manual fix."
        )
        return result

    if not file_path.exists():
        result["message"] = f"File not found: {resolved_file}"
        return result

    if normalized_tool.startswith("eslint"):
        ok, message = await _run_eslint_fix(resolved_file, timeout)
    elif normalized_tool == "semgrep":
        ok, message = await _run_semgrep_autofix(resolved_file, semgrep_config, timeout)
    else:
        ok, message = False, f"No autofix handler for tool: {tool}"

    result["applied"] = ok
    result["message"] = message
    return result
