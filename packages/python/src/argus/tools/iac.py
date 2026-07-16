"""IaC and container scanning tool runners.

Integrates: Checkov (Terraform, CloudFormation, Kubernetes, Dockerfile, Helm),
            Trivy (container image scanning), Terrascan, kube-linter.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from argus.models import Finding, ScanResult, ScanType, Severity
from argus.utils import collect_scan_results, is_tool_available, parse_json_output, run_command

logger = logging.getLogger(__name__)

CHECKOV_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "NONE": Severity.INFO,
}

TRIVY_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.UNKNOWN,
}


async def run_checkov(
    target: str,
    framework: str | None = None,
    timeout: int = 300,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run Checkov for IaC security scanning."""
    result = ScanResult(tool="checkov", scan_type=ScanType.IAC, target=target)

    if not is_tool_available("checkov"):
        result.tool_available = False
        result.errors.append("checkov is not installed. Install with: pip install checkov")
        return result

    target_path = Path(target)
    cmd = [
        "checkov",
        "--output",
        "json",
        "--compact",
        "--quiet",
    ]

    if framework:
        cmd.extend(["--framework", framework])

    if target_path.is_dir():
        cmd.extend(["--directory", target])
    elif target_path.is_file():
        cmd.extend(["--file", target])
    else:
        result.errors.append(f"Target not found: {target}")
        return result

    if extra_args:
        cmd.extend(extra_args)

    code, stdout, stderr = await run_command(cmd, timeout=timeout)
    result.raw_output = stdout

    data = parse_json_output(stdout)
    if not data:
        if code > 1:
            result.errors.append(f"checkov error (exit {code}): {stderr[:400]}")
        return result

    # Checkov returns either a single result object or a list (when multiple frameworks)
    results_list = data if isinstance(data, list) else [data]

    for res in results_list:
        failed_checks = res.get("results", {}).get("failed_checks", [])

        for check in failed_checks:
            sev_str = (
                check.get("severity") or check.get("check_result", {}).get("result", "") or "MEDIUM"
            )
            if not isinstance(sev_str, str):
                sev_str = "MEDIUM"
            sev_str = sev_str.upper()
            severity = CHECKOV_SEVERITY_MAP.get(sev_str, Severity.MEDIUM)

            finding = Finding(
                title=check.get("check_id", "checkov-finding"),
                severity=severity,
                scan_type=ScanType.IAC,
                tool="checkov",
                file=check.get("repo_file_path", check.get("file_path", "")),
                line=check.get("file_line_range", [0])[0] if check.get("file_line_range") else 0,
                description=check.get("check_name", ""),
                rule_id=check.get("check_id", ""),
                fix_guidance=check.get("guideline", ""),
                references=[check.get("guideline", "")] if check.get("guideline") else [],
                raw=check,
            )
            result.findings.append(finding)

    result.metadata["framework"] = framework or "auto"
    return result


async def run_trivy_image(
    image: str,
    timeout: int = 300,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run Trivy container image scan."""
    result = ScanResult(tool="trivy-image", scan_type=ScanType.CONTAINER, target=image)

    if not is_tool_available("trivy"):
        result.tool_available = False
        result.errors.append(
            "trivy is not installed. See https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
        )
        return result

    cmd = [
        "trivy",
        "image",
        "--format",
        "json",
        "--exit-code",
        "0",
        image,
    ]
    if extra_args:
        cmd.extend(extra_args)

    code, stdout, stderr = await run_command(cmd, timeout=timeout)
    result.raw_output = stdout

    data = parse_json_output(stdout)
    if not data:
        if stderr:
            result.errors.append(f"trivy image error: {stderr[:500]}")
        return result

    for report in data.get("Results", []):
        layer = report.get("Target", image)
        for vuln in report.get("Vulnerabilities", []) or []:
            sev_str = vuln.get("Severity", "UNKNOWN").upper()
            severity = TRIVY_SEVERITY_MAP.get(sev_str, Severity.UNKNOWN)

            finding = Finding(
                title=vuln.get("VulnerabilityID", "trivy-image-vuln"),
                severity=severity,
                scan_type=ScanType.CONTAINER,
                tool="trivy-image",
                file=layer,
                description=f"{vuln.get('PkgName', '')}@{vuln.get('InstalledVersion', '')}: {vuln.get('Description', vuln.get('Title', ''))}",
                cve=vuln.get("VulnerabilityID", ""),
                fix_guidance=f"Fix version: {vuln.get('FixedVersion', 'N/A')}",
                references=vuln.get("References", [])[:5],
                rule_id=vuln.get("VulnerabilityID", ""),
                raw=vuln,
            )
            result.findings.append(finding)

    return result


async def run_trivy_config(
    target: str,
    timeout: int = 120,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run Trivy config/misconfiguration scan (IaC)."""
    result = ScanResult(tool="trivy-config", scan_type=ScanType.IAC, target=target)

    if not is_tool_available("trivy"):
        result.tool_available = False
        result.errors.append("trivy is not installed.")
        return result

    cmd = [
        "trivy",
        "config",
        "--format",
        "json",
        "--exit-code",
        "0",
        target,
    ]
    if extra_args:
        cmd.extend(extra_args)

    code, stdout, stderr = await run_command(cmd, timeout=timeout)
    result.raw_output = stdout

    data = parse_json_output(stdout)
    if not data:
        return result

    for report in data.get("Results", []):
        file_path = report.get("Target", "")
        for misconfig in report.get("Misconfigurations", []) or []:
            sev_str = misconfig.get("Severity", "MEDIUM").upper()
            severity = TRIVY_SEVERITY_MAP.get(sev_str, Severity.MEDIUM)

            finding = Finding(
                title=misconfig.get("ID", "trivy-config-finding"),
                severity=severity,
                scan_type=ScanType.IAC,
                tool="trivy-config",
                file=file_path,
                description=misconfig.get("Description", misconfig.get("Title", "")),
                fix_guidance=misconfig.get("Resolution", ""),
                references=misconfig.get("References", [])[:3],
                rule_id=misconfig.get("ID", ""),
                raw=misconfig,
            )
            result.findings.append(finding)

    return result


async def run_terrascan(
    target: str,
    iac_type: str = "all",
    timeout: int = 180,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run Terrascan for IaC security scanning."""
    result = ScanResult(tool="terrascan", scan_type=ScanType.IAC, target=target)

    if not is_tool_available("terrascan"):
        result.tool_available = False
        result.errors.append(
            "terrascan is not installed. See https://runterrascan.io/docs/getting-started/"
        )
        return result

    cmd = [
        "terrascan",
        "scan",
        "--output",
        "json",
        "--iac-dir",
        target,
    ]
    if iac_type != "all":
        cmd.extend(["--iac-type", iac_type])
    if extra_args:
        cmd.extend(extra_args)

    code, stdout, stderr = await run_command(cmd, timeout=timeout)
    result.raw_output = stdout

    data = parse_json_output(stdout)
    if not data:
        if code > 3:
            result.errors.append(f"terrascan error: {stderr[:400]}")
        return result

    violations = (
        data.get("results", {}).get("violations", [])
        if isinstance(data.get("results"), dict)
        else data.get("violations", [])
    )

    sev_map = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }

    for v in violations:
        sev_str = v.get("severity", "MEDIUM").upper()
        severity = sev_map.get(sev_str, Severity.MEDIUM)

        finding = Finding(
            title=v.get("rule_id", v.get("rule_name", "terrascan-finding")),
            severity=severity,
            scan_type=ScanType.IAC,
            tool="terrascan",
            file=v.get("file", ""),
            line=v.get("line", 0),
            description=v.get("description", ""),
            rule_id=v.get("rule_id", ""),
            references=[v.get("rule_reference_id", "")] if v.get("rule_reference_id") else [],
            raw=v,
        )
        result.findings.append(finding)

    return result


async def run_all_iac(
    target: str,
    timeout: int = 300,
) -> list[ScanResult]:
    """Run all available IaC scanning tools.

    Automatically adds Terraform-specific and Ansible-specific scanners
    when the relevant file types are detected in the target directory.
    """
    target_path = Path(target)

    tasks = [
        run_checkov(target, timeout=timeout),
        run_trivy_config(target, timeout=timeout),
        run_terrascan(target, timeout=timeout),
    ]

    # Add Terraform-specific scanners when .tf files are present
    has_tf = (
        bool(list(target_path.rglob("*.tf"))[:1])
        if target_path.is_dir()
        else target_path.suffix == ".tf"
    )
    if has_tf:
        from argus.tools.terraform import run_tflint, run_tfsec

        tasks.append(run_tfsec(target, timeout=timeout))
        tasks.append(run_tflint(target, timeout=min(timeout, 120)))

    # Add Ansible-specific scanners when playbook YAML files are detected
    has_ansible = (
        (
            any(
                (target_path / d).is_dir()
                for d in ("tasks", "roles", "playbooks", "handlers", "vars", "defaults")
            )
            or bool(list(target_path.glob("*.yml"))[:1])
            or bool(list(target_path.glob("*.yaml"))[:1])
        )
        if target_path.is_dir()
        else target_path.suffix in (".yml", ".yaml")
    )
    if has_ansible:
        from argus.tools.ansible import run_ansible_lint

        tasks.append(run_ansible_lint(target, timeout=timeout))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    return collect_scan_results(results, label="IaC scanner")
