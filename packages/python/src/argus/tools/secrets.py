"""Secret scanning tool runners.

Integrates: Gitleaks, detect-secrets, TruffleHog.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from argus.models import Finding, ScanResult, ScanType, Severity
from argus.utils import is_tool_available, parse_json_output, run_command

logger = logging.getLogger(__name__)


async def run_gitleaks(
    target: str,
    timeout: int = 120,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run Gitleaks for secret detection in source code."""
    result = ScanResult(tool="gitleaks", scan_type=ScanType.SECRETS, target=target)

    if not is_tool_available("gitleaks"):
        result.tool_available = False
        result.errors.append(
            "gitleaks is not installed. See https://github.com/gitleaks/gitleaks#installing"
        )
        return result

    target_path = Path(target)
    # Determine if this is a git repo or a plain directory
    is_git = (target_path / ".git").exists()
    subcommand = "detect" if is_git else "detect"

    cmd = [
        "gitleaks",
        subcommand,
        "--source",
        target,
        "--report-format",
        "json",
        "--report-path",
        "/dev/stdout",
        "--exit-code",
        "0",  # Don't fail the process
        "--no-banner",
    ]
    if not is_git:
        cmd.append("--no-git")
    if extra_args:
        cmd.extend(extra_args)

    code, stdout, stderr = await run_command(cmd, timeout=timeout)
    result.raw_output = stdout

    # Gitleaks outputs JSON array to stdout when --report-path /dev/stdout
    data = parse_json_output(stdout)
    if not isinstance(data, list):
        if code > 0:
            result.errors.append(f"gitleaks error (exit {code}): {stderr[:400]}")
        return result

    for leak in data:
        finding = Finding(
            title=leak.get("RuleID", leak.get("rule", "secret-detected")),
            severity=Severity.HIGH,
            scan_type=ScanType.SECRETS,
            tool="gitleaks",
            file=leak.get("File", leak.get("file", "")),
            line=leak.get("StartLine", leak.get("line", 0)),
            description=leak.get(
                "Description",
                leak.get("description", f"Secret detected: {leak.get('Match', '')[:50]}"),
            ),
            rule_id=leak.get("RuleID", ""),
            raw=leak,
        )
        # Redact the actual secret value
        finding.description = (
            finding.description or f"Potential secret matched rule: {finding.rule_id}"
        )
        result.findings.append(finding)

    return result


async def run_detect_secrets(
    target: str,
    timeout: int = 120,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run detect-secrets for secret detection."""
    result = ScanResult(tool="detect-secrets", scan_type=ScanType.SECRETS, target=target)

    if not is_tool_available("detect-secrets"):
        result.tool_available = False
        result.errors.append(
            "detect-secrets is not installed. Install with: pip install detect-secrets"
        )
        return result

    cmd = ["detect-secrets", "scan", target]
    if extra_args:
        cmd.extend(extra_args)

    code, stdout, stderr = await run_command(cmd, timeout=timeout)
    result.raw_output = stdout

    data = parse_json_output(stdout)
    if not data:
        if stderr:
            result.errors.append(f"detect-secrets error: {stderr[:400]}")
        return result

    plugin_map = {
        "ArtifactoryDetector": "Artifactory Credentials",
        "AWSKeyDetector": "AWS Key",
        "AzureStorageKeyDetector": "Azure Storage Key",
        "BasicAuthDetector": "Basic Auth Credentials",
        "CloudantDetector": "Cloudant Credentials",
        "GitHubTokenDetector": "GitHub Token",
        "HexHighEntropyString": "High Entropy Hex String",
        "IbmCloudIamDetector": "IBM Cloud IAM Key",
        "IbmCosHmacDetector": "IBM COS HMAC Credentials",
        "JwtTokenDetector": "JWT Token",
        "KeywordDetector": "Keyword Secret",
        "MailchimpDetector": "Mailchimp API Key",
        "NpmDetector": "NPM Token",
        "PrivateKeyDetector": "Private Key",
        "SendGridDetector": "SendGrid API Key",
        "SlackDetector": "Slack Token",
        "SoftlayerDetector": "Softlayer Credentials",
        "SquareOAuthDetector": "Square OAuth Token",
        "StripeDetector": "Stripe API Key",
        "TwilioKeyDetector": "Twilio API Key",
    }

    for file_path, secrets_list in data.get("results", {}).items():
        for secret in secrets_list:
            detector = secret.get("type", "UnknownDetector")
            description = plugin_map.get(detector, detector)

            finding = Finding(
                title=description,
                severity=Severity.HIGH,
                scan_type=ScanType.SECRETS,
                tool="detect-secrets",
                file=file_path,
                line=secret.get("line_number", 0),
                description=f"Potential {description} found",
                rule_id=detector,
                raw=secret,
            )
            result.findings.append(finding)

    return result


async def run_trufflehog(
    target: str,
    timeout: int = 180,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run TruffleHog for secret detection."""
    result = ScanResult(tool="trufflehog", scan_type=ScanType.SECRETS, target=target)

    if not is_tool_available("trufflehog"):
        result.tool_available = False
        result.errors.append(
            "trufflehog is not installed. See https://github.com/trufflesecurity/trufflehog#installation"
        )
        return result

    target_path = Path(target)
    is_git = (target_path / ".git").exists()
    scheme = "git" if is_git else "filesystem"

    cmd = [
        "trufflehog",
        scheme,
        f"file://{target}" if scheme == "filesystem" else target,
        "--json",
        "--no-update",
    ]
    if extra_args:
        cmd.extend(extra_args)

    code, stdout, stderr = await run_command(cmd, timeout=timeout)
    result.raw_output = stdout

    # TruffleHog outputs newline-delimited JSON
    for line in stdout.strip().splitlines():
        item = parse_json_output(line)
        if not item or not isinstance(item, dict):
            continue

        source_meta = item.get("SourceMetadata", {}).get("Data", {})
        file_info = source_meta.get("Filesystem", {}) or source_meta.get("Git", {}) or {}
        finding = Finding(
            title=item.get("DetectorName", "trufflehog-secret"),
            severity=Severity.CRITICAL,
            scan_type=ScanType.SECRETS,
            tool="trufflehog",
            file=file_info.get("file", file_info.get("filename", "")),
            line=file_info.get("line", 0),
            description=f"Verified={item.get('Verified', False)}: {item.get('DetectorName', '')} secret detected",
            rule_id=item.get("DetectorName", ""),
            raw=item,
        )
        # Upgrade severity if verified
        if item.get("Verified"):
            finding.severity = Severity.CRITICAL
        result.findings.append(finding)

    return result


async def run_all_secrets(
    target: str,
    timeout: int = 180,
) -> list[ScanResult]:
    """Run all available secret scanning tools."""
    tasks = [
        run_gitleaks(target, timeout=timeout),
        run_detect_secrets(target, timeout=timeout),
        run_trufflehog(target, timeout=timeout),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    final: list[ScanResult] = []
    for r in results:
        if isinstance(r, Exception):
            logger.exception("Secret scanner raised an exception: %s", r)
        else:
            final.append(r)
    return final
