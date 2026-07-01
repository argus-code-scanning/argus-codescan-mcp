"""SCA (Software Composition Analysis) tool runners.

Integrates: Trivy (filesystem mode), Safety (Python), pip-audit (Python),
            npm audit (Node.js), OWASP Dependency-Check.
"""

from __future__ import annotations

import logging
from pathlib import Path

from argus.models import Finding, ScanResult, ScanType, Severity
from argus.utils import (
    is_tool_available,
    parse_json_output,
    run_command,
)

logger = logging.getLogger(__name__)

TRIVY_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.UNKNOWN,
}


async def run_trivy_fs(
    target: str,
    timeout: int = 300,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run Trivy filesystem scan for dependency vulnerabilities."""
    result = ScanResult(tool="trivy", scan_type=ScanType.SCA, target=target)

    if not is_tool_available("trivy"):
        result.tool_available = False
        result.errors.append(
            "trivy is not installed. See https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
        )
        return result

    cmd = [
        "trivy",
        "fs",
        "--format",
        "json",
        "--exit-code",
        "0",
        "--scanners",
        "vuln,secret",
        target,
    ]
    if extra_args:
        cmd.extend(extra_args)

    code, stdout, stderr = await run_command(cmd, timeout=timeout)
    result.raw_output = stdout

    data = parse_json_output(stdout)
    if not data:
        if stderr:
            result.errors.append(f"Trivy error: {stderr[:500]}")
        return result

    for report in data.get("Results", []):
        target_file = report.get("Target", "")
        for vuln in report.get("Vulnerabilities", []) or []:
            sev_str = vuln.get("Severity", "UNKNOWN").upper()
            severity = TRIVY_SEVERITY_MAP.get(sev_str, Severity.UNKNOWN)

            finding = Finding(
                title=vuln.get("VulnerabilityID", ""),
                severity=severity,
                scan_type=ScanType.SCA,
                tool="trivy",
                file=target_file,
                description=vuln.get("Description", vuln.get("Title", "")),
                cve=vuln.get("VulnerabilityID", ""),
                fix_guidance=f"Fix version: {vuln.get('FixedVersion', 'N/A')}",
                references=vuln.get("References", [])[:5],
                rule_id=vuln.get("VulnerabilityID", ""),
                raw=vuln,
            )
            # Add package info to description
            pkg_name = vuln.get("PkgName", "")
            installed = vuln.get("InstalledVersion", "")
            if pkg_name:
                finding.description = f"{pkg_name}@{installed}: {finding.description}"
            result.findings.append(finding)

        # Secret findings from Trivy
        for secret in report.get("Secrets", []) or []:
            sev_str = secret.get("Severity", "HIGH").upper()
            severity = TRIVY_SEVERITY_MAP.get(sev_str, Severity.HIGH)
            finding = Finding(
                title=secret.get("RuleID", "secret-detected"),
                severity=severity,
                scan_type=ScanType.SECRETS,
                tool="trivy-secrets",
                file=target_file,
                line=secret.get("StartLine", 0),
                description=secret.get("Title", ""),
                rule_id=secret.get("RuleID", ""),
                raw=secret,
            )
            result.findings.append(finding)

    return result


async def run_safety(
    target: str,
    timeout: int = 120,
) -> ScanResult:
    """Run Safety to check Python dependencies for known vulnerabilities."""
    result = ScanResult(tool="safety", scan_type=ScanType.SCA, target=target)

    if not is_tool_available("safety"):
        result.tool_available = False
        result.errors.append("safety is not installed. Install with: pip install safety")
        return result

    target_path = Path(target)
    req_files = (
        (
            list(target_path.rglob("requirements*.txt"))
            + list(target_path.rglob("Pipfile.lock"))
            + list(target_path.rglob("poetry.lock"))
        )
        if target_path.is_dir()
        else [target_path]
    )

    all_findings: list[Finding] = []

    for req_file in req_files[:5]:  # Limit to 5 files
        cmd = [
            "safety",
            "check",
            "--json",
            "--file",
            str(req_file),
        ]
        code, stdout, stderr = await run_command(cmd, timeout=timeout)

        data = parse_json_output(stdout)
        if not data:
            continue

        vulns = (
            data
            if isinstance(data, list)
            else data.get("vulnerabilities", data.get("affected_packages", []))
        )
        if not isinstance(vulns, list):
            continue

        for vuln in vulns:
            if isinstance(vuln, list) and len(vuln) >= 5:
                # Legacy format: [package, spec, installed, advisory, vuln_id]
                finding = Finding(
                    title=vuln[4] if len(vuln) > 4 else "safety-vuln",
                    severity=Severity.HIGH,
                    scan_type=ScanType.SCA,
                    tool="safety",
                    file=str(req_file),
                    description=vuln[3] if len(vuln) > 3 else "",
                    rule_id=str(vuln[4]) if len(vuln) > 4 else "",
                    raw={"data": vuln},
                )
            elif isinstance(vuln, dict):
                sev = vuln.get("severity", {})
                sev_str = (
                    (sev.get("cvssv3", {}).get("base_severity") or "HIGH").upper()
                    if isinstance(sev, dict)
                    else "HIGH"
                )
                severity = TRIVY_SEVERITY_MAP.get(sev_str, Severity.HIGH)
                finding = Finding(
                    title=vuln.get("vulnerability_id", vuln.get("id", "safety-vuln")),
                    severity=severity,
                    scan_type=ScanType.SCA,
                    tool="safety",
                    file=str(req_file),
                    description=vuln.get("advisory", vuln.get("description", "")),
                    cve=vuln.get("cve", ""),
                    rule_id=vuln.get("vulnerability_id", ""),
                    raw=vuln,
                )
            else:
                continue

            all_findings.append(finding)

    result.findings = all_findings
    return result


async def run_pip_audit(
    target: str,
    timeout: int = 120,
) -> ScanResult:
    """Run pip-audit for Python dependency vulnerability scanning."""
    result = ScanResult(tool="pip-audit", scan_type=ScanType.SCA, target=target)

    if not is_tool_available("pip-audit"):
        result.tool_available = False
        result.errors.append("pip-audit is not installed. Install with: pip install pip-audit")
        return result

    target_path = Path(target)
    req_files = (
        list(target_path.rglob("requirements*.txt"))
        if target_path.is_dir()
        else ([target_path] if target_path.suffix in (".txt", ".lock") else [])
    )

    if not req_files:
        # Audit current environment
        cmd = ["pip-audit", "--format", "json"]
        code, stdout, stderr = await run_command(cmd, timeout=timeout)
    else:
        req_file = req_files[0]
        cmd = ["pip-audit", "--format", "json", "-r", str(req_file)]
        code, stdout, stderr = await run_command(cmd, timeout=timeout)

    result.raw_output = stdout
    data = parse_json_output(stdout)

    if not data:
        if stderr:
            result.errors.append(f"pip-audit error: {stderr[:400]}")
        return result

    deps = data if isinstance(data, list) else data.get("dependencies", [])
    for dep in deps:
        for vuln in dep.get("vulns", []):
            finding = Finding(
                title=vuln.get("id", "pip-audit-vuln"),
                severity=Severity.HIGH,
                scan_type=ScanType.SCA,
                tool="pip-audit",
                description=vuln.get("description", ""),
                cve=vuln.get("id", ""),
                fix_guidance=f"Fix versions: {', '.join(vuln.get('fix_versions', ['N/A']))}",
                rule_id=vuln.get("id", ""),
                raw=vuln,
            )
            # Add package context
            pkg = dep.get("name", "")
            ver = dep.get("version", "")
            if pkg:
                finding.description = f"{pkg}@{ver}: {finding.description}"
            result.findings.append(finding)

    return result


async def run_npm_audit(
    target: str,
    timeout: int = 120,
) -> ScanResult:
    """Run npm audit for Node.js dependency vulnerability scanning."""
    result = ScanResult(tool="npm-audit", scan_type=ScanType.SCA, target=target)

    if not is_tool_available("npm"):
        result.tool_available = False
        result.errors.append("npm is not installed or not on PATH.")
        return result

    target_path = Path(target)
    pkg_json_files = (
        list(target_path.rglob("package.json"))
        if target_path.is_dir()
        else ([target_path] if target_path.name == "package.json" else [])
    )

    if not pkg_json_files:
        result.errors.append("No package.json found in target")
        return result

    cwd = str(pkg_json_files[0].parent)
    cmd = ["npm", "audit", "--json"]
    code, stdout, stderr = await run_command(cmd, cwd=cwd, timeout=timeout)
    result.raw_output = stdout

    data = parse_json_output(stdout)
    if not data:
        result.errors.append(f"npm audit error: {stderr[:400]}")
        return result

    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "moderate": Severity.MEDIUM,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }

    # npm audit v6 format
    vulnerabilities = data.get("vulnerabilities", data.get("advisories", {}))
    if isinstance(vulnerabilities, dict):
        for name, info in vulnerabilities.items():
            if isinstance(info, dict):
                sev_str = info.get("severity", "moderate").lower()
                severity = severity_map.get(sev_str, Severity.MEDIUM)
                via = info.get("via", [])
                description = ""
                cve = ""
                url = ""
                if via and isinstance(via[0], dict):
                    description = via[0].get("title", "")
                    cve = via[0].get("cve", "")
                    url = via[0].get("url", "")

                finding = Finding(
                    title=f"{name}: {description}" if description else name,
                    severity=severity,
                    scan_type=ScanType.SCA,
                    tool="npm-audit",
                    file=str(pkg_json_files[0]),
                    description=description,
                    cve=cve,
                    fix_guidance=str(info.get("fixAvailable", "Check npm audit fix")),
                    references=[url] if url else [],
                    raw=info,
                )
                result.findings.append(finding)

    return result


async def run_all_sca(
    target: str,
    timeout: int = 300,
) -> list[ScanResult]:
    """Run all available SCA tools against a target."""
    import asyncio

    tasks = [
        run_trivy_fs(target, timeout=timeout),
        run_safety(target, timeout=timeout),
        run_pip_audit(target, timeout=timeout),
        run_npm_audit(target, timeout=timeout),
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)
    final: list[ScanResult] = []
    for r in results:
        if isinstance(r, Exception):
            logger.exception("SCA tool raised an exception: %s", r)
        else:
            final.append(r)
    return final
