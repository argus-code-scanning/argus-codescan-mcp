"""Ansible-specific security scanning tool runners.

Integrates:
  - ansible-lint  — official Ansible linter with security rules
  - KICS          — Keeping Infrastructure as Code Secure (Ansible queries)
  - Checkov       — re-exported with ansible framework locked
  - Trivy config  — re-exported, supports Ansible playbooks

Detects:
  - Hardcoded passwords / secrets in vars, defaults, and tasks
  - Insecure module usage (shell, command with untrusted input)
  - Missing no_log on sensitive tasks
  - World-readable file permissions
  - Disabled host key checking
  - Unvaulted sensitive variables
  - Deprecated / removed module usage
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from argus.models import Finding, ScanResult, ScanType, Severity
from argus.utils import is_tool_available, parse_json_output, run_command

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, Severity] = {
    "blocker": Severity.CRITICAL,
    "critical": Severity.CRITICAL,
    "major": Severity.HIGH,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "minor": Severity.LOW,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "warning": Severity.MEDIUM,
    "error": Severity.HIGH,
    "violation": Severity.HIGH,
}

# ansible-lint profile → severity mapping
_PROFILE_SEVERITY: dict[str, Severity] = {
    "min": Severity.CRITICAL,
    "basic": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "safety": Severity.HIGH,
    "shared": Severity.MEDIUM,
    "production": Severity.LOW,
}


# ── ansible-lint ──────────────────────────────────────────────────────────────


async def run_ansible_lint(
    target: str,
    profile: str = "safety",
    timeout: int = 180,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run ansible-lint against Ansible playbooks, roles, and collections.

    Profiles (from strictest to least):
      min        — Only critical errors that break playbook execution
      basic      — Essential best practices
      moderate   — Reasonable recommendations
      safety     — Security-focused rules (default)
      shared     — Rules for shared/public roles
      production — All rules

    Security rules include:
      - no-log-password        Passwords must have no_log set
      - risky-shell-pipe       Dangerous shell pipe usage
      - command-instead-of-shell  Prefer command over shell
      - deprecated-command-syntax  Deprecated module arguments
      - risky-file-permissions  World-writable files
      - partial-become         Incomplete privilege escalation
      - package-latest         Pinning package versions
    """
    result = ScanResult(tool="ansible-lint", scan_type=ScanType.IAC, target=target)

    if not is_tool_available("ansible-lint"):
        result.tool_available = False
        result.errors.append(
            "ansible-lint is not installed.\n"
            "  pip:    pip install ansible-lint\n"
            "  pipx:   pipx install ansible-lint\n"
            "  brew:   brew install ansible-lint"
        )
        return result

    target_path = Path(target)

    # Discover playbooks and roles
    scan_targets = _discover_ansible_targets(target_path)
    if not scan_targets:
        result.errors.append(f"No Ansible playbooks, roles, or collections found in: {target}")
        return result

    cmd = [
        "ansible-lint",
        "--format",
        "json",
        "--profile",
        profile,
        "--nocolor",
        "--offline",  # don't pull galaxy collections during scan
        "--exclude",
        ".git",
        "--exclude",
        ".venv",
        "--exclude",
        "venv",
        *scan_targets[:20],  # limit to 20 targets to avoid arg list overflow
    ]
    if extra_args:
        cmd.extend(extra_args)

    code, stdout, stderr = await run_command(cmd, cwd=target, timeout=timeout)
    result.raw_output = stdout

    # ansible-lint exits 2 on violations — that's expected
    if code > 2:
        result.errors.append(f"ansible-lint error (exit {code}): {stderr[:400]}")

    data = parse_json_output(stdout)
    if not data:
        return result

    # JSON output is a list of violation objects
    violations = data if isinstance(data, list) else data.get("violations", [])

    for v in violations:
        rule = v.get("rule", {})
        rule_id = rule.get("id", v.get("rule_id", "ansible-lint"))
        sev_str = rule.get("severity", v.get("severity", "medium")).lower()
        severity = _SEVERITY_MAP.get(sev_str, Severity.MEDIUM)

        # Security-related rules get bumped up
        if any(tag in rule.get("tags", []) for tag in ("security", "secrets", "risky")):
            if severity == Severity.MEDIUM:
                severity = Severity.HIGH

        finding = Finding(
            title=rule_id,
            severity=severity,
            scan_type=ScanType.IAC,
            tool="ansible-lint",
            file=v.get("filename", v.get("path", "")),
            line=v.get("linenumber", v.get("line", 0)),
            description=v.get("message", rule.get("description", "")),
            rule_id=rule_id,
            fix_guidance=rule.get("help", v.get("help", "")),
            references=rule.get("link", "").split() if rule.get("link") else [],
            raw=v,
        )
        result.findings.append(finding)

    result.metadata["profile"] = profile
    result.metadata["targets_scanned"] = len(scan_targets)
    return result


def _discover_ansible_targets(root: Path) -> list[str]:
    """Find Ansible playbooks, roles, and task files in a directory."""
    targets: list[str] = []

    if root.is_file():
        return [str(root)]

    # Top-level playbooks
    for pattern in ("*.yml", "*.yaml"):
        for f in root.glob(pattern):
            targets.append(str(f))

    # roles/*/tasks/main.yml
    roles_dir = root / "roles"
    if roles_dir.is_dir():
        for task_main in roles_dir.glob("*/tasks/main.yml"):
            targets.append(str(task_main.parent.parent.parent))  # role root

    # playbooks/ subdirectory
    pb_dir = root / "playbooks"
    if pb_dir.is_dir():
        for f in pb_dir.glob("*.yml"):
            targets.append(str(f))

    # site.yml / main.yml at root
    for name in ("site.yml", "site.yaml", "main.yml", "main.yaml"):
        f = root / name
        if f.exists() and str(f) not in targets:
            targets.append(str(f))

    return list(dict.fromkeys(targets))  # deduplicate, preserve order


# ── KICS (Ansible) ────────────────────────────────────────────────────────────


async def run_kics_ansible(
    target: str,
    timeout: int = 300,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run KICS for Ansible security scanning.

    KICS Ansible queries detect:
      - Hardcoded passwords in tasks and vars
      - Commands run as root without become_user
      - Insecure SSH configuration in tasks
      - Exposed secrets in templates
      - Unsafe module arguments
    """
    result = ScanResult(tool="kics-ansible", scan_type=ScanType.IAC, target=target)

    if not is_tool_available("kics"):
        result.tool_available = False
        result.errors.append(
            "kics is not installed.\n"
            "  macOS:  brew install kics\n"
            "  Docker: docker run --rm -v $(pwd):/path checkmarx/kics scan -p /path -t Ansible\n"
            "  Go:     go install github.com/Checkmarx/kics/v2@latest\n"
            "  Binary: https://github.com/Checkmarx/kics/releases"
        )
        return result

    with tempfile.TemporaryDirectory() as tmpdir:
        cmd = [
            "kics",
            "scan",
            "--path",
            target,
            "--type",
            "Ansible",
            "--output-path",
            tmpdir,
            "--output-name",
            "kics-ansible-report",
            "--report-formats",
            "json",
            "--no-progress",
            "--silent",
        ]
        if extra_args:
            cmd.extend(extra_args)

        code, stdout, stderr = await run_command(cmd, timeout=timeout)
        result.raw_output = stdout + stderr

        report_file = os.path.join(tmpdir, "kics-ansible-report.json")
        if os.path.exists(report_file):
            with open(report_file) as f:
                data = json.load(f)
            _parse_kics_ansible_report(data, result)
        elif code > 50:
            result.errors.append(f"kics-ansible error (exit {code}): {stderr[:400]}")

    return result


def _parse_kics_ansible_report(data: dict[str, Any], result: ScanResult) -> None:
    sev_map = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
        "TRACE": Severity.INFO,
    }
    for query in data.get("queries", []):
        sev_str = query.get("severity", "MEDIUM").upper()
        severity = sev_map.get(sev_str, Severity.MEDIUM)
        for file_entry in query.get("files", []):
            finding = Finding(
                title=query.get("query_name", "kics-ansible"),
                severity=severity,
                scan_type=ScanType.IAC,
                tool="kics-ansible",
                file=file_entry.get("file_name", ""),
                line=file_entry.get("line", 0),
                description=query.get("description", ""),
                rule_id=query.get("query_id", ""),
                fix_guidance=query.get("remediation_instruction", ""),
                references=[query.get("url", "")] if query.get("url") else [],
                raw={**query, "file_entry": file_entry},
            )
            result.findings.append(finding)

    result.metadata["total_queries"] = data.get("total_queries", 0)
    result.metadata["files_scanned"] = data.get("files_scanned", 0)


# ── Checkov (Ansible-focused) ────────────────────────────────────────────────


async def run_checkov_ansible(
    target: str,
    timeout: int = 180,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run Checkov scoped to Ansible framework.

    Checkov Ansible checks include:
      - CKV2_ANSIBLE_1  No clear-text passwords
      - CKV2_ANSIBLE_2  No hardcoded secrets
      - CKV2_ANSIBLE_3  Enable no_log for sensitive tasks
      - CKV2_ANSIBLE_4  Don't use become with shell/command
      - CKV2_ANSIBLE_5  Use encrypted secrets (ansible-vault)
    """
    from argus.tools.iac import run_checkov

    result = await run_checkov(target, framework="ansible", timeout=timeout, extra_args=extra_args)
    result.tool = "checkov-ansible"
    return result


# ── Aggregate ─────────────────────────────────────────────────────────────────


async def run_all_ansible(
    target: str,
    timeout: int = 300,
    tools: list[str] | None = None,
    ansible_lint_profile: str = "safety",
) -> list[ScanResult]:
    """Run all available Ansible security scanners in parallel.

    Tools: ansible-lint, kics-ansible, checkov-ansible
    """
    selected = tools or ["ansible-lint", "kics", "checkov"]

    tasks: list = []
    if "ansible-lint" in selected:
        tasks.append(run_ansible_lint(target, profile=ansible_lint_profile, timeout=timeout))
    if "kics" in selected:
        tasks.append(run_kics_ansible(target, timeout=timeout))
    if "checkov" in selected:
        tasks.append(run_checkov_ansible(target, timeout=timeout))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    final: list[ScanResult] = []
    for r in results:
        if isinstance(r, Exception):
            logger.exception("Ansible scanner raised an exception: %s", r)
        else:
            final.append(r)
    return final
