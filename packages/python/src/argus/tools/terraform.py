"""Terraform-specific security scanning tool runners.

Integrates:
  - tfsec      — Terraform static analysis (standalone + embedded in Trivy)
  - tflint     — Terraform linter with security rule plugins
  - terraform validate — built-in Terraform syntax/config validation
  - terraform-compliance — BDD-style policy testing
  - KICS       — Keeping Infrastructure as Code Secure (multi-framework)
  - Checkov    — re-exported with terraform framework locked
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from argus.models import Finding, ScanResult, ScanType, Severity
from argus.utils import collect_scan_results, is_tool_available, parse_json_output, run_command

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "WARNING": Severity.MEDIUM,
    "ERROR": Severity.HIGH,
    "INFO": Severity.INFO,
    "NOTICE": Severity.INFO,
}


# ── tfsec ────────────────────────────────────────────────────────────────────


async def run_tfsec(
    target: str,
    timeout: int = 180,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run tfsec for Terraform static security analysis.

    tfsec checks for misconfigurations such as:
      - Unencrypted S3 buckets / EBS volumes / RDS instances
      - Publicly exposed resources
      - Missing logging / audit trails
      - Insecure security group rules (0.0.0.0/0)
      - Hardcoded sensitive values
    """
    result = ScanResult(tool="tfsec", scan_type=ScanType.IAC, target=target)

    if not is_tool_available("tfsec"):
        result.tool_available = False
        result.errors.append(
            "tfsec is not installed.\n"
            "  macOS:  brew install tfsec\n"
            "  Linux:  curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash\n"
            "  Go:     go install github.com/aquasecurity/tfsec/cmd/tfsec@latest\n"
            "  Docker: docker run --rm -v $(pwd):/src aquasec/tfsec /src\n"
            "  Note:   tfsec is also embedded in Trivy (trivy config --scanners misconfig)"
        )
        return result

    cmd = [
        "tfsec",
        "--format",
        "json",
        "--no-colour",
        "--soft-fail",  # exit 0 even with findings
        target,
    ]
    if extra_args:
        cmd.extend(extra_args)

    code, stdout, stderr = await run_command(cmd, timeout=timeout)
    result.raw_output = stdout

    data = parse_json_output(stdout)
    if not data:
        if code > 0 and stderr:
            result.errors.append(f"tfsec error (exit {code}): {stderr[:400]}")
        return result

    results = data.get("results", [])
    for item in results:
        sev_str = item.get("severity", "MEDIUM").upper()
        severity = _SEVERITY_MAP.get(sev_str, Severity.MEDIUM)

        location = item.get("location", {})
        refs = item.get("links", [])

        finding = Finding(
            title=item.get("rule_id", item.get("long_id", "tfsec-finding")),
            severity=severity,
            scan_type=ScanType.IAC,
            tool="tfsec",
            file=location.get("filename", ""),
            line=location.get("start_line", 0),
            description=item.get("description", item.get("rule_description", "")),
            rule_id=item.get("rule_id", item.get("long_id", "")),
            fix_guidance=item.get("resolution", ""),
            references=refs[:5] if refs else [],
            raw=item,
        )
        result.findings.append(finding)

    result.metadata["tfsec_version"] = data.get("tfsec_version", "unknown")
    return result


# ── tflint ───────────────────────────────────────────────────────────────────


async def run_tflint(
    target: str,
    timeout: int = 120,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run tflint for Terraform linting with security rules.

    tflint detects:
      - Provider-specific issues (AWS, GCP, Azure deprecated resources)
      - Undeclared variables, unused declarations
      - Invalid resource arguments
      - Naming convention violations
    """
    result = ScanResult(tool="tflint", scan_type=ScanType.IAC, target=target)

    if not is_tool_available("tflint"):
        result.tool_available = False
        result.errors.append(
            "tflint is not installed.\n"
            "  macOS:  brew install tflint\n"
            "  Linux:  curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash\n"
            "  Go:     go install github.com/terraform-linters/tflint@latest"
        )
        return result

    cmd = [
        "tflint",
        "--format",
        "json",
        "--chdir",
        target,
    ]
    if extra_args:
        cmd.extend(extra_args)

    code, stdout, stderr = await run_command(cmd, cwd=target, timeout=timeout)
    result.raw_output = stdout

    data = parse_json_output(stdout)
    if not data:
        if stderr:
            result.errors.append(f"tflint error: {stderr[:400]}")
        return result

    rule_sev_map = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "notice": Severity.LOW}

    for issue in data.get("issues", []):
        rule = issue.get("rule", {})
        sev_str = rule.get("severity", "warning").lower()
        severity = rule_sev_map.get(sev_str, Severity.MEDIUM)

        pos = issue.get("range", {}).get("start", {})
        finding = Finding(
            title=rule.get("name", "tflint-finding"),
            severity=severity,
            scan_type=ScanType.IAC,
            tool="tflint",
            file=issue.get("range", {}).get("filename", ""),
            line=pos.get("line", 0),
            column=pos.get("column", 0),
            description=issue.get("message", ""),
            rule_id=rule.get("name", ""),
            references=[rule.get("link", "")] if rule.get("link") else [],
            raw=issue,
        )
        result.findings.append(finding)

    return result


# ── terraform validate ────────────────────────────────────────────────────────


async def run_terraform_validate(
    target: str,
    timeout: int = 60,
) -> ScanResult:
    """Run `terraform validate` for syntax and configuration checking.

    Catches:
      - Syntax errors in .tf files
      - Invalid resource attribute values
      - Missing required arguments
      - Unsupported argument references
    """
    result = ScanResult(tool="terraform-validate", scan_type=ScanType.IAC, target=target)

    if not is_tool_available("terraform"):
        result.tool_available = False
        result.errors.append(
            "terraform is not installed.\n"
            "  macOS:  brew install terraform\n"
            "  Linux:  https://developer.hashicorp.com/terraform/downloads\n"
            "  tfenv:  brew install tfenv && tfenv install latest"
        )
        return result

    # terraform validate requires `terraform init` first; run a minimal init
    init_code, _, init_stderr = await run_command(
        ["terraform", "init", "-backend=false", "-input=false", "-no-color"],
        cwd=target,
        timeout=60,
    )
    if init_code != 0:
        result.errors.append(f"terraform init failed: {init_stderr[:400]}")
        # Continue anyway — validate may still produce useful output

    code, stdout, stderr = await run_command(
        ["terraform", "validate", "-json", "-no-color"],
        cwd=target,
        timeout=timeout,
    )
    result.raw_output = stdout

    data = parse_json_output(stdout)
    if not data:
        if stderr:
            result.errors.append(f"terraform validate error: {stderr[:400]}")
        return result

    result.metadata["valid"] = data.get("valid", False)
    result.metadata["error_count"] = data.get("error_count", 0)
    result.metadata["warning_count"] = data.get("warning_count", 0)

    for diag in data.get("diagnostics", []):
        sev_str = diag.get("severity", "error").lower()
        severity = Severity.HIGH if sev_str == "error" else Severity.LOW

        rng = diag.get("range", {})
        finding = Finding(
            title=diag.get("summary", "terraform-validate-issue"),
            severity=severity,
            scan_type=ScanType.IAC,
            tool="terraform-validate",
            file=rng.get("filename", ""),
            line=rng.get("start", {}).get("line", 0),
            description=diag.get("detail", ""),
            rule_id="TF-VALIDATE",
            raw=diag,
        )
        result.findings.append(finding)

    return result


# ── KICS ─────────────────────────────────────────────────────────────────────


async def run_kics_terraform(
    target: str,
    timeout: int = 300,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run KICS (Keeping Infrastructure as Code Secure) for Terraform.

    KICS contains 2000+ queries covering Terraform for AWS, GCP, Azure,
    and many other providers. Detects:
      - Public network exposure
      - Missing encryption
      - Overly permissive IAM policies
      - Disabled logging / monitoring
      - Insecure TLS configuration
    """
    result = ScanResult(tool="kics", scan_type=ScanType.IAC, target=target)

    if not is_tool_available("kics"):
        result.tool_available = False
        result.errors.append(
            "kics is not installed.\n"
            "  macOS:  brew install kics\n"
            "  Docker: docker run --rm -v $(pwd):/path checkmarx/kics scan -p /path\n"
            "  Go:     go install github.com/Checkmarx/kics/v2@latest\n"
            "  Binary: https://github.com/Checkmarx/kics/releases"
        )
        return result

    import os
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        report_file = os.path.join(tmpdir, "kics-report.json")
        cmd = [
            "kics",
            "scan",
            "--path",
            target,
            "--type",
            "Terraform",
            "--output-path",
            tmpdir,
            "--output-name",
            "kics-report",
            "--report-formats",
            "json",
            "--no-progress",
            "--silent",
        ]
        if extra_args:
            cmd.extend(extra_args)

        code, stdout, stderr = await run_command(cmd, timeout=timeout)
        result.raw_output = stdout + stderr

        if os.path.exists(report_file):
            with open(report_file) as f:
                data = json.load(f)
            _parse_kics_report(data, result)
        elif code > 50:
            result.errors.append(f"kics error (exit {code}): {stderr[:400]}")

    return result


def _parse_kics_report(data: dict[str, Any], result: ScanResult) -> None:
    """Parse KICS JSON report into normalised findings."""
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
                title=query.get("query_name", "kics-finding"),
                severity=severity,
                scan_type=ScanType.IAC,
                tool="kics",
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
    result.metadata["kics_version"] = data.get("kics_version", "unknown")


# ── Checkov (Terraform-focused) ───────────────────────────────────────────────


async def run_checkov_terraform(
    target: str,
    timeout: int = 180,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run Checkov scoped to Terraform framework only."""
    from argus.tools.iac import run_checkov

    result = await run_checkov(
        target, framework="terraform", timeout=timeout, extra_args=extra_args
    )
    result.tool = "checkov-terraform"
    return result


# ── Aggregate ────────────────────────────────────────────────────────────────


async def run_all_terraform(
    target: str,
    timeout: int = 300,
    tools: list[str] | None = None,
) -> list[ScanResult]:
    """Run all available Terraform security scanners in parallel.

    Tools: tfsec, tflint, terraform-validate, kics, checkov-terraform
    """
    available_tools = tools or ["tfsec", "tflint", "terraform-validate", "kics", "checkov"]

    tasks: list = []
    if "tfsec" in available_tools:
        tasks.append(run_tfsec(target, timeout=timeout))
    if "tflint" in available_tools:
        tasks.append(run_tflint(target, timeout=min(timeout, 120)))
    if "terraform-validate" in available_tools:
        tasks.append(run_terraform_validate(target, timeout=min(timeout, 60)))
    if "kics" in available_tools:
        tasks.append(run_kics_terraform(target, timeout=timeout))
    if "checkov" in available_tools:
        tasks.append(run_checkov_terraform(target, timeout=timeout))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    return collect_scan_results(results, label="Terraform scanner")
