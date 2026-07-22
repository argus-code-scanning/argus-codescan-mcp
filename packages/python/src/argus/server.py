"""MCP server exposing security scanning tools.

This server implements the Model Context Protocol (MCP) and exposes
security scanning capabilities (SAST, DAST, SCA, Secrets, IaC) as
MCP tools that AI assistants can call.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions

from argus.cloud_upload import ScanTimer, upload_scan_report
from argus.models import AggregatedReport
from argus.tools.ansible import (
    run_all_ansible,
    run_ansible_lint,
    run_checkov_ansible,
    run_kics_ansible,
)
from argus.tools.dast import run_all_dast, run_nikto, run_zap_baseline
from argus.tools.fix import apply_finding_fix
from argus.tools.iac import (
    run_all_iac,
    run_checkov,
    run_terrascan,
    run_trivy_config,
    run_trivy_image,
)
from argus.tools.sast import (
    run_all_sast,
    run_bandit,
    run_eslint_security,
    run_semgrep,
)
from argus.tools.sca import (
    run_all_sca,
    run_npm_audit,
    run_pip_audit,
    run_safety,
    run_trivy_fs,
)
from argus.tools.secrets import (
    run_all_secrets,
    run_detect_secrets,
    run_gitleaks,
    run_trufflehog,
)
from argus.tools.terraform import (
    run_all_terraform,
    run_checkov_terraform,
    run_kics_terraform,
    run_terraform_validate,
    run_tflint,
    run_tfsec,
)
from argus.utils import collect_scan_results, format_markdown_report, is_tool_available

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

server = Server("argus-scan")


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="scan_sast",
            description=(
                "Run Static Application Security Testing (SAST) on source code. "
                "Detects vulnerabilities in code logic, insecure functions, injection flaws, "
                "hardcoded credentials, and more. Supports Python (Bandit, Semgrep), "
                "JavaScript/TypeScript (ESLint security), and all languages via Semgrep."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Absolute path to file or directory to scan",
                    },
                    "tools": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["semgrep", "bandit", "eslint"]},
                        "description": "Specific tools to run (default: all applicable)",
                    },
                    "semgrep_config": {
                        "type": "string",
                        "description": "Semgrep ruleset config (default: 'auto'). Examples: 'auto', 'p/owasp-top-ten', 'p/python', 'p/javascript'",
                        "default": "auto",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds per tool (default: 300)",
                        "default": 300,
                    },
                    "format": {
                        "type": "string",
                        "enum": ["markdown", "json"],
                        "description": "Output format (default: markdown)",
                        "default": "markdown",
                    },
                },
                "required": ["target"],
            },
        ),
        types.Tool(
            name="scan_dast",
            description=(
                "Run Dynamic Application Security Testing (DAST) against a live web application URL. "
                "Detects XSS, SQL injection, CSRF, insecure headers, and other runtime vulnerabilities. "
                "Uses OWASP ZAP (via Docker or local install) and Nikto. "
                "The target URL must be a running application."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL of the running web application to scan (e.g. http://localhost:3000)",
                    },
                    "tools": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["zap", "nikto"]},
                        "description": "Specific tools to run (default: all available)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 600 for DAST scans)",
                        "default": 600,
                    },
                },
                "required": ["target_url"],
            },
        ),
        types.Tool(
            name="scan_sca",
            description=(
                "Run Software Composition Analysis (SCA) to detect vulnerabilities in "
                "third-party dependencies and open-source libraries. Checks requirements.txt, "
                "package.json, Pipfile, poetry.lock, etc. Uses Trivy, Safety, pip-audit, and npm audit."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Path to project directory or dependency file",
                    },
                    "tools": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["trivy", "safety", "pip-audit", "npm-audit"],
                        },
                        "description": "Specific tools to run (default: all applicable)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 300)",
                        "default": 300,
                    },
                },
                "required": ["target"],
            },
        ),
        types.Tool(
            name="scan_secrets",
            description=(
                "Scan source code for leaked secrets, API keys, passwords, tokens, and credentials. "
                "Uses Gitleaks, detect-secrets, and TruffleHog. Works on both git repos and plain directories."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Path to directory or git repository to scan",
                    },
                    "tools": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["gitleaks", "detect-secrets", "trufflehog"],
                        },
                        "description": "Specific tools to run (default: all available)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 180)",
                        "default": 180,
                    },
                },
                "required": ["target"],
            },
        ),
        types.Tool(
            name="scan_iac",
            description=(
                "Scan Infrastructure-as-Code files for security misconfigurations. "
                "Supports Terraform, CloudFormation, Kubernetes, Dockerfile, Helm, Ansible, and ARM templates. "
                "Uses Checkov, Trivy config scan, and Terrascan."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Path to IaC file or directory",
                    },
                    "framework": {
                        "type": "string",
                        "description": "IaC framework: terraform, cloudformation, kubernetes, dockerfile, helm, ansible (default: auto-detect)",
                    },
                    "tools": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["checkov", "trivy-config", "terrascan"],
                        },
                        "description": "Specific tools to run (default: all available)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 300)",
                        "default": 300,
                    },
                },
                "required": ["target"],
            },
        ),
        types.Tool(
            name="scan_container",
            description=(
                "Scan a container image for OS package vulnerabilities, CVEs, and misconfigurations. "
                "Uses Trivy image scan. Supports Docker Hub images, local images, and registry images."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "image": {
                        "type": "string",
                        "description": "Container image name (e.g. nginx:latest, myapp:1.0, ghcr.io/org/image:tag)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 300)",
                        "default": 300,
                    },
                },
                "required": ["image"],
            },
        ),
        types.Tool(
            name="scan_terraform",
            description=(
                "Run a comprehensive security scan on Terraform infrastructure code (.tf files). "
                "Detects misconfigurations such as public S3 buckets, unencrypted volumes, "
                "overly permissive IAM policies, missing logging, insecure security group rules, "
                "and hardcoded secrets. Uses tfsec, tflint, terraform validate, KICS, and Checkov."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Path to Terraform directory or .tf file",
                    },
                    "tools": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["tfsec", "tflint", "terraform-validate", "kics", "checkov"],
                        },
                        "description": "Specific tools to run (default: all available)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds per tool (default: 300)",
                        "default": 300,
                    },
                },
                "required": ["target"],
            },
        ),
        types.Tool(
            name="scan_ansible",
            description=(
                "Run a security scan on Ansible playbooks, roles, and collections. "
                "Detects hardcoded passwords, missing no_log on sensitive tasks, insecure shell usage, "
                "risky file permissions, unvaulted secrets, and deprecated module usage. "
                "Uses ansible-lint, KICS, and Checkov."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Path to Ansible playbook, role directory, or project root",
                    },
                    "tools": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["ansible-lint", "kics", "checkov"],
                        },
                        "description": "Specific tools to run (default: all available)",
                    },
                    "ansible_lint_profile": {
                        "type": "string",
                        "enum": ["min", "basic", "moderate", "safety", "shared", "production"],
                        "description": "ansible-lint strictness profile (default: safety)",
                        "default": "safety",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds per tool (default: 300)",
                        "default": 300,
                    },
                },
                "required": ["target"],
            },
        ),
        types.Tool(
            name="scan_all",
            description=(
                "Run a comprehensive security scan combining SAST, SCA, secret scanning, and IaC checks "
                "on a code directory. Optionally include DAST if a URL is provided. "
                "Returns an aggregated report with findings from all tools."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Path to project directory to scan",
                    },
                    "target_url": {
                        "type": "string",
                        "description": "Optional: URL of running app for DAST scan",
                    },
                    "container_image": {
                        "type": "string",
                        "description": "Optional: container image name for image scan",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds per tool (default: 300)",
                        "default": 300,
                    },
                    "format": {
                        "type": "string",
                        "enum": ["markdown", "json"],
                        "description": "Output format (default: markdown)",
                        "default": "markdown",
                    },
                },
                "required": ["target"],
            },
        ),
        types.Tool(
            name="check_tools",
            description=(
                "Check which security scanning tools are installed and available on the system. "
                "Returns availability status and installation instructions for any missing tools."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        types.Tool(
            name="get_scan_report",
            description=(
                "Retrieve a formatted security report from a previous scan result JSON. "
                "Converts raw JSON scan data into a readable Markdown report."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_result_json": {
                        "type": "string",
                        "description": "JSON string from a previous scan result",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["markdown", "json"],
                        "description": "Output format",
                        "default": "markdown",
                    },
                },
                "required": ["scan_result_json"],
            },
        ),
        types.Tool(
            name="apply_fix",
            description=(
                "Apply or preview a fix for a specific scan finding. "
                "Only call this when the user explicitly asks to fix a finding — "
                "scans never modify files automatically. "
                "Set apply=false (default) to return fix guidance only; "
                "set apply=true only after the user confirms they want an automated fix."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Project root or scan target path",
                    },
                    "file": {
                        "type": "string",
                        "description": "File path from the finding",
                    },
                    "tool": {
                        "type": "string",
                        "description": "Scanner tool name from the finding (e.g. semgrep, eslint-security)",
                    },
                    "scan_type": {
                        "type": "string",
                        "description": "Scan type from the finding (sast, sca, secrets, iac, etc.)",
                        "default": "sast",
                    },
                    "rule_id": {
                        "type": "string",
                        "description": "Rule ID from the finding",
                        "default": "",
                    },
                    "line": {
                        "type": "integer",
                        "description": "Line number from the finding",
                        "default": 0,
                    },
                    "fix_guidance": {
                        "type": "string",
                        "description": "Fix guidance text from the finding",
                        "default": "",
                    },
                    "apply": {
                        "type": "boolean",
                        "description": "If true, run an automated fix (user must have confirmed)",
                        "default": False,
                    },
                    "semgrep_config": {
                        "type": "string",
                        "description": "Semgrep config when fixing semgrep findings",
                        "default": "auto",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds for fix commands",
                        "default": 120,
                    },
                },
                "required": ["target", "file", "tool"],
            },
        ),
    ]


# ---------------------------------------------------------------------------
# Tool call handler
# ---------------------------------------------------------------------------


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
    """Dispatch tool calls to the appropriate scanner."""
    try:
        if name == "scan_sast":
            return await _handle_scan_sast(arguments)
        elif name == "scan_dast":
            return await _handle_scan_dast(arguments)
        elif name == "scan_sca":
            return await _handle_scan_sca(arguments)
        elif name == "scan_secrets":
            return await _handle_scan_secrets(arguments)
        elif name == "scan_iac":
            return await _handle_scan_iac(arguments)
        elif name == "scan_terraform":
            return await _handle_scan_terraform(arguments)
        elif name == "scan_ansible":
            return await _handle_scan_ansible(arguments)
        elif name == "scan_container":
            return await _handle_scan_container(arguments)
        elif name == "scan_all":
            return await _handle_scan_all(arguments)
        elif name == "check_tools":
            return await _handle_check_tools()
        elif name == "get_scan_report":
            return await _handle_get_scan_report(arguments)
        elif name == "apply_fix":
            return await _handle_apply_fix(arguments)
        else:
            return [types.TextContent(type="text", text=f"Unknown tool: {name}")]
    except Exception as exc:
        logger.exception("Error in tool %s", name)
        return [types.TextContent(type="text", text=f"Error running {name}: {exc}")]


# ---------------------------------------------------------------------------
# Individual handlers
# ---------------------------------------------------------------------------


async def _finish_scan(
    report: AggregatedReport,
    *,
    scan_type: str,
    timer: ScanTimer,
    fmt: str = "markdown",
    fail_on: str | None = None,
    include_raw_json: bool = False,
) -> list[types.TextContent]:
    """Format scan output and optionally upload to the cloud dashboard."""
    report_dict = report.to_dict()
    upload_note = ""

    try:
        upload_status = await upload_scan_report(
            report_dict,
            duration_sec=timer.elapsed,
            fail_on=fail_on,
            scan_type=scan_type,
            target=report.target,
        )
        if upload_status:
            upload_note = f"\n\n☁️ **Cloud dashboard:** {upload_status}"
            logger.info("Cloud upload: %s", upload_status)
    except Exception as exc:
        logger.warning("Cloud upload failed: %s", exc)
        upload_note = f"\n\n⚠️ Cloud upload failed: {exc}"

    if fmt == "json":
        text = json.dumps(report_dict, indent=2)
        if upload_note:
            text += upload_note
        return [types.TextContent(type="text", text=text)]

    md = format_markdown_report(report_dict) + upload_note
    parts: list[types.TextContent] = [types.TextContent(type="text", text=md)]
    if include_raw_json:
        parts.append(
            types.TextContent(
                type="text",
                text=(
                    f"\n\n<details><summary>Raw JSON</summary>\n\n```json\n"
                    f"{json.dumps(report_dict, indent=2)}\n```\n\n</details>"
                ),
            )
        )
    return parts


async def _handle_scan_sast(args: dict[str, Any]) -> list[types.TextContent]:
    timer = ScanTimer()
    target = args["target"]
    tools = args.get("tools")
    semgrep_config = args.get("semgrep_config", "auto")
    timeout = int(args.get("timeout", 300))
    fmt = args.get("format", "markdown")

    if tools:
        tasks = []
        if "semgrep" in tools:
            tasks.append(run_semgrep(target, config=semgrep_config, timeout=timeout))
        if "bandit" in tools:
            tasks.append(run_bandit(target, timeout=timeout))
        if "eslint" in tools:
            tasks.append(run_eslint_security(target, timeout=timeout))
        results = collect_scan_results(await asyncio.gather(*tasks, return_exceptions=True))
    else:
        results = await run_all_sast(target, semgrep_config=semgrep_config, timeout=timeout)

    report = AggregatedReport(target=target, results=list(results))
    return await _finish_scan(
        report,
        scan_type="sast",
        timer=timer,
        fmt=fmt,
        fail_on=args.get("fail_on"),
        include_raw_json=True,
    )


async def _handle_scan_dast(args: dict[str, Any]) -> list[types.TextContent]:
    timer = ScanTimer()
    target_url = args["target_url"]
    tools = args.get("tools")
    timeout = int(args.get("timeout", 600))

    if tools:
        tasks = []
        if "zap" in tools:
            tasks.append(run_zap_baseline(target_url, timeout=timeout))
        if "nikto" in tools:
            tasks.append(run_nikto(target_url, timeout=min(timeout, 300)))
        results = collect_scan_results(await asyncio.gather(*tasks, return_exceptions=True))
    else:
        results = await run_all_dast(target_url, timeout=timeout)

    report = AggregatedReport(target=target_url, results=list(results))
    return await _finish_scan(
        report,
        scan_type="dast",
        timer=timer,
        fmt=args.get("format", "markdown"),
        fail_on=args.get("fail_on"),
    )


async def _handle_scan_sca(args: dict[str, Any]) -> list[types.TextContent]:
    timer = ScanTimer()
    target = args["target"]
    tools = args.get("tools")
    timeout = int(args.get("timeout", 300))

    if tools:
        tasks = []
        if "trivy" in tools:
            tasks.append(run_trivy_fs(target, timeout=timeout))
        if "safety" in tools:
            tasks.append(run_safety(target, timeout=timeout))
        if "pip-audit" in tools:
            tasks.append(run_pip_audit(target, timeout=timeout))
        if "npm-audit" in tools:
            tasks.append(run_npm_audit(target, timeout=timeout))
        results = collect_scan_results(await asyncio.gather(*tasks, return_exceptions=True))
    else:
        results = await run_all_sca(target, timeout=timeout)

    report = AggregatedReport(target=target, results=list(results))
    return await _finish_scan(
        report,
        scan_type="sca",
        timer=timer,
        fmt=args.get("format", "markdown"),
        fail_on=args.get("fail_on"),
    )


async def _handle_scan_secrets(args: dict[str, Any]) -> list[types.TextContent]:
    timer = ScanTimer()
    target = args["target"]
    tools = args.get("tools")
    timeout = int(args.get("timeout", 180))

    if tools:
        tasks = []
        if "gitleaks" in tools:
            tasks.append(run_gitleaks(target, timeout=timeout))
        if "detect-secrets" in tools:
            tasks.append(run_detect_secrets(target, timeout=timeout))
        if "trufflehog" in tools:
            tasks.append(run_trufflehog(target, timeout=timeout))
        results = collect_scan_results(await asyncio.gather(*tasks, return_exceptions=True))
    else:
        results = await run_all_secrets(target, timeout=timeout)

    report = AggregatedReport(target=target, results=list(results))
    return await _finish_scan(
        report,
        scan_type="secrets",
        timer=timer,
        fmt=args.get("format", "markdown"),
        fail_on=args.get("fail_on"),
    )


async def _handle_scan_iac(args: dict[str, Any]) -> list[types.TextContent]:
    timer = ScanTimer()
    target = args["target"]
    framework = args.get("framework")
    tools = args.get("tools")
    timeout = int(args.get("timeout", 300))

    if tools:
        tasks = []
        if "checkov" in tools:
            tasks.append(run_checkov(target, framework=framework, timeout=timeout))
        if "trivy-config" in tools:
            tasks.append(run_trivy_config(target, timeout=timeout))
        if "terrascan" in tools:
            tasks.append(run_terrascan(target, timeout=timeout))
        results = collect_scan_results(await asyncio.gather(*tasks, return_exceptions=True))
    else:
        results = await run_all_iac(target, timeout=timeout)

    report = AggregatedReport(target=target, results=list(results))
    return await _finish_scan(
        report,
        scan_type="iac",
        timer=timer,
        fmt=args.get("format", "markdown"),
        fail_on=args.get("fail_on"),
    )


async def _handle_scan_terraform(args: dict[str, Any]) -> list[types.TextContent]:
    timer = ScanTimer()
    target = args["target"]
    tools = args.get("tools")
    timeout = int(args.get("timeout", 300))

    if tools:
        tasks = []
        if "tfsec" in tools:
            tasks.append(run_tfsec(target, timeout=timeout))
        if "tflint" in tools:
            tasks.append(run_tflint(target, timeout=min(timeout, 120)))
        if "terraform-validate" in tools:
            tasks.append(run_terraform_validate(target, timeout=min(timeout, 60)))
        if "kics" in tools:
            tasks.append(run_kics_terraform(target, timeout=timeout))
        if "checkov" in tools:
            tasks.append(run_checkov_terraform(target, timeout=timeout))
        results = collect_scan_results(await asyncio.gather(*tasks, return_exceptions=True))
    else:
        results = await run_all_terraform(target, timeout=timeout)

    report = AggregatedReport(target=target, results=list(results))
    return await _finish_scan(
        report,
        scan_type="terraform",
        timer=timer,
        fmt=args.get("format", "markdown"),
        fail_on=args.get("fail_on"),
    )


async def _handle_scan_ansible(args: dict[str, Any]) -> list[types.TextContent]:
    timer = ScanTimer()
    target = args["target"]
    tools = args.get("tools")
    timeout = int(args.get("timeout", 300))
    profile = args.get("ansible_lint_profile", "safety")

    if tools:
        tasks = []
        if "ansible-lint" in tools:
            tasks.append(run_ansible_lint(target, profile=profile, timeout=timeout))
        if "kics" in tools:
            tasks.append(run_kics_ansible(target, timeout=timeout))
        if "checkov" in tools:
            tasks.append(run_checkov_ansible(target, timeout=timeout))
        results = collect_scan_results(await asyncio.gather(*tasks, return_exceptions=True))
    else:
        results = await run_all_ansible(target, timeout=timeout, ansible_lint_profile=profile)

    report = AggregatedReport(target=target, results=list(results))
    return await _finish_scan(
        report,
        scan_type="ansible",
        timer=timer,
        fmt=args.get("format", "markdown"),
        fail_on=args.get("fail_on"),
    )


async def _handle_scan_container(args: dict[str, Any]) -> list[types.TextContent]:
    timer = ScanTimer()
    image = args["image"]
    timeout = int(args.get("timeout", 300))

    result = await run_trivy_image(image, timeout=timeout)
    report = AggregatedReport(target=image, results=[result])
    return await _finish_scan(
        report,
        scan_type="container",
        timer=timer,
        fmt=args.get("format", "markdown"),
        fail_on=args.get("fail_on"),
    )


async def _handle_scan_all(args: dict[str, Any]) -> list[types.TextContent]:
    timer = ScanTimer()
    target = args["target"]
    target_url = args.get("target_url")
    container_image = args.get("container_image")
    timeout = int(args.get("timeout", 300))
    fmt = args.get("format", "markdown")

    all_results = []

    # Run code-level scans in parallel
    code_tasks = [
        run_all_sast(target, timeout=timeout),
        run_all_sca(target, timeout=timeout),
        run_all_secrets(target, timeout=timeout),
        run_all_iac(target, timeout=timeout),
    ]
    code_scan_results = await asyncio.gather(*code_tasks, return_exceptions=True)
    for batch in code_scan_results:
        if isinstance(batch, list):
            all_results.extend(batch)

    # Optional DAST
    if target_url:
        dast_results = await run_all_dast(target_url, timeout=min(timeout, 600))
        all_results.extend(dast_results)

    # Optional container scan
    if container_image:
        container_result = await run_trivy_image(container_image, timeout=timeout)
        all_results.append(container_result)

    report = AggregatedReport(target=target, results=all_results)
    return await _finish_scan(
        report,
        scan_type="all",
        timer=timer,
        fmt=fmt,
        fail_on=args.get("fail_on"),
    )


TOOLS_REGISTRY: dict[str, dict[str, str]] = {
    "semgrep": {
        "category": "SAST",
        "install": "pip install semgrep",
        "docs": "https://semgrep.dev/docs/getting-started/",
    },
    "bandit": {
        "category": "SAST (Python)",
        "install": "pip install bandit",
        "docs": "https://bandit.readthedocs.io/",
    },
    "flake8": {
        "category": "SAST (Python)",
        "install": "pip install flake8 flake8-bandit",
        "docs": "https://flake8.pycqa.org/",
    },
    "eslint": {
        "category": "SAST (JS/TS)",
        "install": "npm install -g eslint eslint-plugin-security",
        "docs": "https://github.com/eslint-community/eslint-plugin-security",
    },
    "trivy": {
        "category": "SCA / IaC / Container",
        "install": "brew install trivy  OR  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh",
        "docs": "https://aquasecurity.github.io/trivy/",
    },
    "safety": {
        "category": "SCA (Python)",
        "install": "pip install safety",
        "docs": "https://pyup.io/safety/",
    },
    "pip-audit": {
        "category": "SCA (Python)",
        "install": "pip install pip-audit",
        "docs": "https://pypi.org/project/pip-audit/",
    },
    "npm": {
        "category": "SCA (Node.js)",
        "install": "Install Node.js from https://nodejs.org/",
        "docs": "https://docs.npmjs.com/cli/v10/commands/npm-audit",
    },
    "gitleaks": {
        "category": "Secret Scanning",
        "install": "brew install gitleaks  OR  go install github.com/gitleaks/gitleaks/v8@latest",
        "docs": "https://github.com/gitleaks/gitleaks",
    },
    "detect-secrets": {
        "category": "Secret Scanning",
        "install": "pip install detect-secrets",
        "docs": "https://github.com/Yelp/detect-secrets",
    },
    "trufflehog": {
        "category": "Secret Scanning",
        "install": "brew install trufflehog  OR  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
        "docs": "https://github.com/trufflesecurity/trufflehog",
    },
    "checkov": {
        "category": "IaC / Terraform / Ansible",
        "install": "pip install checkov",
        "docs": "https://www.checkov.io/",
    },
    "terrascan": {
        "category": "IaC",
        "install": "brew install terrascan  OR  curl -L https://github.com/tenable/terrascan/releases/latest/download/terrascan_Linux_x86_64.tar.gz | tar -xz",
        "docs": "https://runterrascan.io/",
    },
    "tfsec": {
        "category": "Terraform SAST",
        "install": "brew install tfsec  OR  go install github.com/aquasecurity/tfsec/cmd/tfsec@latest",
        "docs": "https://aquasecurity.github.io/tfsec/",
    },
    "tflint": {
        "category": "Terraform Linter",
        "install": "brew install tflint  OR  curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash",
        "docs": "https://github.com/terraform-linters/tflint",
    },
    "terraform": {
        "category": "Terraform (validate)",
        "install": "brew install terraform  OR  https://developer.hashicorp.com/terraform/downloads",
        "docs": "https://developer.hashicorp.com/terraform/cli/commands/validate",
    },
    "kics": {
        "category": "IaC / Terraform / Ansible (KICS)",
        "install": "brew install kics  OR  go install github.com/Checkmarx/kics/v2@latest",
        "docs": "https://kics.io/",
    },
    "ansible-lint": {
        "category": "Ansible",
        "install": "pip install ansible-lint  OR  pipx install ansible-lint",
        "docs": "https://ansible.readthedocs.io/projects/lint/",
    },
    "docker": {
        "category": "DAST / Container (required for ZAP)",
        "install": "https://docs.docker.com/get-docker/",
        "docs": "https://www.zaproxy.org/docs/docker/baseline-scan/",
    },
    "nikto": {
        "category": "DAST",
        "install": "brew install nikto  OR  apt install nikto",
        "docs": "https://cirt.net/Nikto2",
    },
}


async def _handle_check_tools() -> list[types.TextContent]:
    lines = ["# Security Tool Availability\n"]
    lines.append("| Tool | Category | Status | Install Command |")
    lines.append("|------|----------|--------|-----------------|")

    available_count = 0
    for tool, info in TOOLS_REGISTRY.items():
        available = is_tool_available(tool)
        status = "✅ Installed" if available else "❌ Not installed"
        if available:
            available_count += 1
        install = info["install"] if not available else "—"
        lines.append(f"| `{tool}` | {info['category']} | {status} | `{install}` |")

    lines.append(f"\n**{available_count}/{len(TOOLS_REGISTRY)} tools installed.**\n")

    if available_count < len(TOOLS_REGISTRY):
        lines.append("\n## Quick Install (missing tools)\n")
        lines.append("```bash")
        for tool, info in TOOLS_REGISTRY.items():
            if not is_tool_available(tool):
                lines.append(f"# {tool} ({info['category']})")
                lines.append(info["install"])
        lines.append("```")

    return [types.TextContent(type="text", text="\n".join(lines))]


async def _handle_get_scan_report(args: dict[str, Any]) -> list[types.TextContent]:
    try:
        data = json.loads(args["scan_result_json"])
    except json.JSONDecodeError as e:
        return [types.TextContent(type="text", text=f"Invalid JSON: {e}")]

    fmt = args.get("format", "markdown")
    if fmt == "json":
        return [types.TextContent(type="text", text=json.dumps(data, indent=2))]

    md = format_markdown_report(data)
    return [types.TextContent(type="text", text=md)]


async def _handle_apply_fix(args: dict[str, Any]) -> list[types.TextContent]:
    result = await apply_finding_fix(
        target=args["target"],
        file=args["file"],
        tool=args["tool"],
        scan_type=args.get("scan_type", "sast"),
        rule_id=args.get("rule_id", ""),
        line=int(args.get("line", 0)),
        fix_guidance=args.get("fix_guidance", ""),
        apply=bool(args.get("apply", False)),
        semgrep_config=args.get("semgrep_config", "auto"),
        timeout=int(args.get("timeout", 120)),
    )
    return [types.TextContent(type="text", text=json.dumps(result, indent=2))]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main() -> None:
    """Run the MCP server over stdio."""
    logger.info("Starting argus-scan server")
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="argus-scan",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


def run() -> None:
    """Synchronous entry point for CLI."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
