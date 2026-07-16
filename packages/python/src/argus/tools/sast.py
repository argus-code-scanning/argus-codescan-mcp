"""SAST (Static Application Security Testing) tool runners.

Integrates: Semgrep, Bandit (Python), ESLint security plugin (JS/TS),
            SpotBugs/FindSecBugs (Java, via CLI), PMD (multi-language).
"""

from __future__ import annotations

import logging
from pathlib import Path

from argus.models import Finding, ScanResult, ScanType, Severity
from argus.utils import (
    collect_scan_results,
    is_tool_available,
    parse_json_output,
    run_command,
)

logger = logging.getLogger(__name__)

SEVERITY_MAP_SEMGREP: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.INFO,
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

SEVERITY_MAP_BANDIT: dict[str, Severity] = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


async def run_semgrep(
    target: str,
    config: str = "auto",
    timeout: int = 300,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run Semgrep SAST scan."""
    result = ScanResult(tool="semgrep", scan_type=ScanType.SAST, target=target)

    if not is_tool_available("semgrep"):
        result.tool_available = False
        result.errors.append("semgrep is not installed. Install with: pip install semgrep")
        return result

    cmd = [
        "semgrep",
        "--json",
        "--config",
        config,
        "--timeout",
        str(timeout),
        "--no-git-ignore",
        target,
    ]
    if extra_args:
        cmd.extend(extra_args)

    code, stdout, stderr = await run_command(cmd, timeout=timeout + 30)
    result.raw_output = stdout
    result.metadata["exit_code"] = code

    if stderr and code not in (0, 1):
        result.errors.append(stderr[:500])

    data = parse_json_output(stdout)
    if not data:
        if code not in (0, 1):
            result.errors.append(f"Semgrep returned non-zero exit code {code}")
        return result

    for item in data.get("results", []):
        extra = item.get("extra", {})
        sev_str = extra.get("severity", item.get("severity", "INFO")).upper()
        severity = SEVERITY_MAP_SEMGREP.get(sev_str, Severity.INFO)

        metadata = extra.get("metadata", {})
        references = metadata.get("references", [])
        if isinstance(references, str):
            references = [references]

        finding = Finding(
            title=item.get("check_id", "semgrep-finding"),
            severity=severity,
            scan_type=ScanType.SAST,
            tool="semgrep",
            file=item.get("path", ""),
            line=item.get("start", {}).get("line", 0),
            column=item.get("start", {}).get("col", 0),
            description=extra.get("message", ""),
            rule_id=item.get("check_id", ""),
            cwe=str(metadata.get("cwe", "")),
            fix_guidance=extra.get("fix", ""),
            references=references,
            raw=item,
        )
        result.findings.append(finding)

    for err in data.get("errors", []):
        result.errors.append(err.get("message", str(err))[:300])

    return result


async def run_bandit(
    target: str,
    severity_level: str = "l",
    confidence_level: str = "l",
    timeout: int = 120,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run Bandit Python SAST scan."""
    result = ScanResult(tool="bandit", scan_type=ScanType.SAST, target=target)

    if not is_tool_available("bandit"):
        result.tool_available = False
        result.errors.append("bandit is not installed. Install with: pip install bandit")
        return result

    target_path = Path(target)
    confidence_flag = {"l": "-i", "m": "-ii", "h": "-iii"}.get(confidence_level, "-i")
    cmd = [
        "bandit",
        "--format",
        "json",
        f"-{severity_level}",
        confidence_flag,
    ]
    if target_path.is_dir():
        cmd.extend(["-r", target])
    else:
        cmd.append(target)

    if extra_args:
        cmd.extend(extra_args)

    code, stdout, stderr = await run_command(cmd, timeout=timeout)
    result.raw_output = stdout
    result.metadata["exit_code"] = code

    data = parse_json_output(stdout)
    if not data:
        if code > 1:
            result.errors.append(f"Bandit error (exit {code}): {stderr[:400]}")
        return result

    for item in data.get("results", []):
        sev_str = item.get("issue_severity", "LOW").upper()
        severity = SEVERITY_MAP_BANDIT.get(sev_str, Severity.LOW)

        finding = Finding(
            title=item.get("test_name", "bandit-finding"),
            severity=severity,
            scan_type=ScanType.SAST,
            tool="bandit",
            file=item.get("filename", ""),
            line=item.get("line_number", 0),
            description=item.get("issue_text", ""),
            rule_id=item.get("test_id", ""),
            cwe=item.get("issue_cwe", {}).get("id", "")
            if isinstance(item.get("issue_cwe"), dict)
            else str(item.get("issue_cwe", "")),
            references=item.get("more_info", "").split(",") if item.get("more_info") else [],
            raw=item,
        )
        result.findings.append(finding)

    metrics = data.get("metrics", {})
    result.metadata["metrics"] = metrics

    return result


async def run_eslint_security(
    target: str,
    timeout: int = 120,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run ESLint with security plugin for JS/TS scanning."""
    result = ScanResult(tool="eslint-security", scan_type=ScanType.SAST, target=target)

    eslint_cmd = "eslint" if is_tool_available("eslint") else None
    if not eslint_cmd:
        result.tool_available = False
        result.errors.append(
            "eslint is not installed. Install with: npm install -g eslint eslint-plugin-security"
        )
        return result

    target_path = Path(target)
    glob_pattern = "**/*.{js,jsx,ts,tsx,mjs,cjs}" if target_path.is_dir() else target

    cmd = [
        eslint_cmd,
        "--format",
        "json",
        "--plugin",
        "security",
        "--rule",
        '{"security/detect-object-injection": "warn", "security/detect-non-literal-regexp": "warn", "security/detect-non-literal-require": "warn", "security/detect-possible-timing-attacks": "warn", "security/detect-eval-with-expression": "error", "security/detect-no-csrf-before-method-override": "error", "security/detect-buffer-noassert": "error", "security/detect-child-process": "warn", "security/detect-disable-mustache-escape": "error", "security/detect-new-buffer": "error", "security/detect-pseudoRandomBytes": "warn", "security/detect-unsafe-regex": "warn"}',
        glob_pattern,
    ]
    if extra_args:
        cmd.extend(extra_args)

    code, stdout, stderr = await run_command(
        cmd, cwd=target if target_path.is_dir() else None, timeout=timeout
    )
    result.raw_output = stdout
    result.metadata["exit_code"] = code

    data = parse_json_output(stdout)
    if not isinstance(data, list):
        if stderr:
            result.errors.append(f"ESLint error: {stderr[:400]}")
        return result

    severity_map = {1: Severity.LOW, 2: Severity.HIGH}

    for file_result in data:
        file_path = file_result.get("filePath", "")
        for msg in file_result.get("messages", []):
            rule = msg.get("ruleId", "")
            if not rule or not rule.startswith("security/"):
                continue

            sev_num = msg.get("severity", 1)
            severity = severity_map.get(sev_num, Severity.MEDIUM)

            finding = Finding(
                title=rule,
                severity=severity,
                scan_type=ScanType.SAST,
                tool="eslint-security",
                file=file_path,
                line=msg.get("line", 0),
                column=msg.get("column", 0),
                description=msg.get("message", ""),
                rule_id=rule,
                raw=msg,
            )
            result.findings.append(finding)

    return result


async def run_flake8_security(
    target: str,
    timeout: int = 120,
) -> ScanResult:
    """Run flake8 with flake8-bandit (pep8 + security checks) for Python."""
    result = ScanResult(tool="flake8-bandit", scan_type=ScanType.SAST, target=target)

    if not is_tool_available("flake8"):
        result.tool_available = False
        result.errors.append(
            "flake8 is not installed. Install with: pip install flake8 flake8-bandit"
        )
        return result

    target_path = Path(target)
    cmd = ["flake8", "--select=S", "--format=%(path)s:%(row)d:%(col)d: %(code)s %(text)s"]
    if target_path.is_dir():
        cmd.append(target)
    else:
        cmd.append(target)

    code, stdout, stderr = await run_command(cmd, timeout=timeout)
    result.raw_output = stdout

    for line in stdout.strip().splitlines():
        parts = line.split(":", 3)
        if len(parts) < 4:
            continue
        file_, row, col, message = parts
        rule_match = message.strip().split(" ", 1)
        rule_id = rule_match[0] if rule_match else ""

        finding = Finding(
            title=rule_id or "flake8-security",
            severity=Severity.MEDIUM,
            scan_type=ScanType.SAST,
            tool="flake8-bandit",
            file=file_.strip(),
            line=int(row) if row.isdigit() else 0,
            column=int(col) if col.isdigit() else 0,
            description=message.strip(),
            rule_id=rule_id,
        )
        result.findings.append(finding)

    return result


async def run_all_sast(
    target: str,
    semgrep_config: str = "auto",
    timeout: int = 300,
) -> list[ScanResult]:
    """Run all available SAST tools against a target."""
    import asyncio

    from argus.tools.code import run_native_languages

    target_path = Path(target)
    tasks = []

    # Built-in multi-language scanner (Java, PHP, Terraform, Ansible, …) — always runs
    tasks.append(run_native_languages(target))

    # Always try Semgrep (multi-language)
    tasks.append(run_semgrep(target, config=semgrep_config, timeout=timeout))

    # Language-specific tools
    py_files = (
        list(target_path.rglob("*.py"))
        if target_path.is_dir()
        else ([target_path] if target_path.suffix == ".py" else [])
    )
    if py_files:
        tasks.append(run_bandit(target, timeout=timeout))
        tasks.append(run_flake8_security(target, timeout=timeout))

    js_files = (
        (
            list(target_path.rglob("*.js"))
            + list(target_path.rglob("*.ts"))
            + list(target_path.rglob("*.jsx"))
            + list(target_path.rglob("*.tsx"))
        )
        if target_path.is_dir()
        else ([target_path] if target_path.suffix in (".js", ".ts", ".jsx", ".tsx") else [])
    )
    if js_files:
        tasks.append(run_eslint_security(target, timeout=timeout))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    return collect_scan_results(results, label="SAST tool")
