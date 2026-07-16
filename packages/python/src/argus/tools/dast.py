"""DAST (Dynamic Application Security Testing) tool runners.

Integrates: OWASP ZAP (via python-owasp-zap-v2.4 or CLI),
            Nikto (web server scanner).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

from argus.models import Finding, ScanResult, ScanType, Severity
from argus.utils import collect_scan_results, is_tool_available, parse_json_output, run_command

logger = logging.getLogger(__name__)


ZAP_RISK_MAP: dict[str, Severity] = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
}


async def run_zap_baseline(
    target_url: str,
    zap_path: str | None = None,
    timeout: int = 600,
    output_file: str | None = None,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run OWASP ZAP baseline scan against a URL.

    Tries Docker first (most reliable), then local CLI.
    """
    result = ScanResult(tool="owasp-zap", scan_type=ScanType.DAST, target=target_url)

    # Try Docker-based ZAP first
    if is_tool_available("docker"):
        return await _run_zap_docker(target_url, timeout, output_file, extra_args, result)

    # Try local zap.sh / zap-baseline.py
    zap_executable = zap_path or _find_zap_cli()
    if zap_executable:
        return await _run_zap_cli(
            target_url, zap_executable, timeout, output_file, extra_args, result
        )

    # Try python-owasp-zap-v2.4 library (requires ZAP running externally)
    import importlib.util

    if importlib.util.find_spec("zapv2") is not None:
        result.errors.append(
            "ZAP API library found but no running ZAP instance detected. "
            "Start ZAP with: docker run -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080"
        )

    result.tool_available = False
    result.errors.append(
        "OWASP ZAP is not available. Install options:\n"
        "  1. Docker: docker pull ghcr.io/zaproxy/zaproxy:stable\n"
        "  2. Package manager: brew install owasp-zap (macOS)\n"
        "  3. Download: https://www.zaproxy.org/download/\n"
        "  4. Python API: pip install python-owasp-zap-v2.4"
    )
    return result


async def _run_zap_docker(
    target_url: str,
    timeout: int,
    output_file: str | None,
    extra_args: list[str] | None,
    result: ScanResult,
) -> ScanResult:
    """Run ZAP via Docker container."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{tmpdir}:/zap/wrk/:rw",
            "ghcr.io/zaproxy/zaproxy:stable",
            "zap-baseline.py",
            "-t",
            target_url,
            "-J",
            "zap-report.json",
            "-I",  # Don't fail on warnings
        ]
        if extra_args:
            cmd.extend(extra_args)

        code, stdout, stderr = await run_command(cmd, timeout=timeout)
        result.raw_output = stdout + stderr

        # Read the report file
        docker_report = os.path.join(tmpdir, "zap-report.json")
        if os.path.exists(docker_report):
            with open(docker_report) as f:
                data = json.load(f)
            _parse_zap_json(data, result)
        elif code not in (0, 2):  # ZAP exits 2 on warnings
            result.errors.append(f"ZAP docker scan failed (exit {code}): {stderr[:400]}")

    return result


async def _run_zap_cli(
    target_url: str,
    zap_executable: str,
    timeout: int,
    output_file: str | None,
    extra_args: list[str] | None,
    result: ScanResult,
) -> ScanResult:
    """Run ZAP via local CLI."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = os.path.join(tmpdir, "zap-report.json")

        cmd = [
            zap_executable,
            "-t",
            target_url,
            "-J",
            report_path,
            "-I",
        ]
        if extra_args:
            cmd.extend(extra_args)

        code, stdout, stderr = await run_command(cmd, timeout=timeout)
        result.raw_output = stdout + stderr

        if os.path.exists(report_path):
            with open(report_path) as f:
                data = json.load(f)
            _parse_zap_json(data, result)
        elif code not in (0, 2):
            result.errors.append(f"ZAP CLI scan failed (exit {code})")

    return result


def _find_zap_cli() -> str | None:
    """Find the ZAP baseline script in common locations."""
    candidates = [
        "zap-baseline.py",
        "/usr/local/bin/zap-baseline.py",
        "/opt/homebrew/bin/zap-baseline.py",
        "/Applications/ZAP.app/Contents/Java/zap-baseline.py",
    ]
    for c in candidates:
        if os.path.isfile(c) or is_tool_available(c):
            return c
    return None


def _parse_zap_json(data: dict[str, Any], result: ScanResult) -> None:
    """Parse ZAP JSON report into findings."""
    for site in data.get("site", []):
        site_name = site.get("@name", "")
        for alert in site.get("alerts", []):
            risk_str = alert.get("riskcode", alert.get("risk", "1"))
            severity = ZAP_RISK_MAP.get(str(risk_str), Severity.INFO)

            instances = alert.get("instances", [{}])
            for instance in instances[:10]:  # Limit to 10 instances per alert
                uri = instance.get("uri", site_name)
                finding = Finding(
                    title=alert.get("name", "zap-finding"),
                    severity=severity,
                    scan_type=ScanType.DAST,
                    tool="owasp-zap",
                    file=uri,
                    description=alert.get("desc", ""),
                    fix_guidance=alert.get("solution", ""),
                    cwe=str(alert.get("cweid", "")),
                    rule_id=str(alert.get("pluginid", "")),
                    references=[alert.get("reference", "")][:3] if alert.get("reference") else [],
                    raw=alert,
                )
                result.findings.append(finding)


async def run_nikto(
    target_url: str,
    timeout: int = 300,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run Nikto web server vulnerability scanner."""
    result = ScanResult(tool="nikto", scan_type=ScanType.DAST, target=target_url)

    if not is_tool_available("nikto"):
        result.tool_available = False
        result.errors.append(
            "nikto is not installed. Install with: brew install nikto (macOS) or apt install nikto (Debian/Ubuntu)"
        )
        return result

    cmd = ["nikto", "-host", target_url, "-Format", "json", "-output", "/dev/stdout"]
    if extra_args:
        cmd.extend(extra_args)

    code, stdout, stderr = await run_command(cmd, timeout=timeout)
    result.raw_output = stdout

    # Nikto JSON output varies by version
    data = parse_json_output(stdout)
    if data:
        vulnerabilities = data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            finding = Finding(
                title=vuln.get("id", "nikto-finding"),
                severity=Severity.MEDIUM,
                scan_type=ScanType.DAST,
                tool="nikto",
                file=target_url,
                description=vuln.get("msg", vuln.get("description", "")),
                rule_id=str(vuln.get("id", "")),
                references=[vuln.get("url", "")] if vuln.get("url") else [],
                raw=vuln,
            )
            result.findings.append(finding)
    else:
        # Parse text output
        for line in stdout.splitlines():
            if line.startswith("+") and ("OSVDB" in line or "CVE" in line):
                finding = Finding(
                    title="nikto-finding",
                    severity=Severity.MEDIUM,
                    scan_type=ScanType.DAST,
                    tool="nikto",
                    file=target_url,
                    description=line.strip("+ "),
                )
                result.findings.append(finding)

    return result


async def run_all_dast(
    target_url: str,
    timeout: int = 600,
) -> list[ScanResult]:
    """Run all available DAST tools against a URL target."""
    tasks = [
        run_zap_baseline(target_url, timeout=timeout),
        run_nikto(target_url, timeout=min(timeout, 300)),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return collect_scan_results(results, label="DAST tool")
