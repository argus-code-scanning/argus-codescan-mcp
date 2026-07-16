"""Standalone CLI for argus-scan.

Runs security scans directly from the terminal — no AI, no token,
no subscription needed. Just Python + the open-source scanner tools.

Usage:
    argus scan code /path/to/flutter-app   # Dart + Android/iOS Flutter config     # built-in Java, PHP, Terraform, Ansible, …
    argus scan sca  /path/to/project
    argus scan secrets /path/to/repo
    argus scan iac /path/to/infra
    argus scan terraform /path/to/tf
    argus scan ansible /path/to/playbooks
    argus scan all /path/to/project
    argus scan dast http://localhost:3000
    argus scan container nginx:latest
    argus tools        # list installed scanners
    argus mcp          # start MCP server (for AI clients)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from argus.models import AggregatedReport
from argus.utils import format_markdown_report, is_tool_available


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argus",
        description=(
            "Code security scanner — SAST, DAST, SCA, Secrets, IaC, Terraform, Ansible.\n"
            "All scanners are open-source. No AI token or subscription needed for CLI use."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="store_true", help="Print version and exit")

    sub = parser.add_subparsers(dest="command", metavar="command")

    # ── scan ────────────────────────────────────────────────────────────────
    scan_p = sub.add_parser("scan", help="Run a security scan")
    scan_sub = scan_p.add_subparsers(dest="scan_type", metavar="type")

    # Common flags shared by most scan subcommands
    def _add_common(p: argparse.ArgumentParser, has_target: bool = True) -> None:
        if has_target:
            p.add_argument("target", help="Path to file, directory, URL, or image to scan")
        p.add_argument(
            "--format",
            "-f",
            choices=["markdown", "json", "table"],
            default="markdown",
            help="Output format (default: markdown)",
        )
        p.add_argument(
            "--timeout",
            "-t",
            type=int,
            default=300,
            help="Timeout in seconds per tool (default: 300)",
        )
        p.add_argument(
            "--output",
            "-o",
            metavar="FILE",
            help="Write output to FILE instead of stdout",
        )
        p.add_argument(
            "--min-severity",
            "-s",
            choices=["critical", "high", "medium", "low", "info"],
            default="low",
            help="Only show findings at or above this severity (default: low)",
        )
        p.add_argument(
            "--tools",
            metavar="TOOL",
            nargs="+",
            help="Run only specific tools (space-separated)",
        )
        p.add_argument(
            "--fail-on",
            choices=["critical", "high", "medium", "low", "never"],
            default="never",
            help="Exit with code 1 if findings at this severity or above are found",
        )

    sast_p = scan_sub.add_parser("sast", help="Static Application Security Testing")
    _add_common(sast_p)
    sast_p.add_argument("--semgrep-config", default="auto", help="Semgrep ruleset (default: auto)")

    code_p = scan_sub.add_parser(
        "code",
        help="Built-in multi-language code scan (Java, PHP, Terraform, Ansible, … — no extra tools)",
    )
    _add_common(code_p)

    sca_p = scan_sub.add_parser("sca", help="Software Composition Analysis (dependencies)")
    _add_common(sca_p)

    sec_p = scan_sub.add_parser("secrets", help="Secret / credential scanning")
    _add_common(sec_p)

    iac_p = scan_sub.add_parser("iac", help="Infrastructure-as-Code scanning")
    _add_common(iac_p)
    iac_p.add_argument(
        "--framework", help="IaC framework: terraform, kubernetes, dockerfile, helm, ansible…"
    )

    tf_p = scan_sub.add_parser("terraform", help="Terraform-specific security scan")
    _add_common(tf_p)

    ans_p = scan_sub.add_parser("ansible", help="Ansible playbook / role security scan")
    _add_common(ans_p)
    ans_p.add_argument(
        "--profile",
        choices=["min", "basic", "moderate", "safety", "shared", "production"],
        default="safety",
        help="ansible-lint profile (default: safety)",
    )

    dast_p = scan_sub.add_parser("dast", help="Dynamic Application Security Testing (live URL)")
    _add_common(dast_p)

    ctr_p = scan_sub.add_parser("container", help="Container image vulnerability scan")
    _add_common(ctr_p)

    all_p = scan_sub.add_parser("all", help="Run all applicable scans")
    _add_common(all_p)
    all_p.add_argument("--url", metavar="URL", help="Also run DAST against this URL")
    all_p.add_argument("--image", metavar="IMAGE", help="Also scan this container image")

    # ── tools ───────────────────────────────────────────────────────────────
    sub.add_parser("tools", help="List installed security tools and their status")

    # ── mcp ─────────────────────────────────────────────────────────────────
    mcp_p = sub.add_parser("mcp", help="Start the MCP server (for AI clients like Cursor / Claude)")
    mcp_p.add_argument(
        "--config",
        action="store_true",
        help="Print ready-to-paste MCP client config JSON and exit",
    )

    return parser


# ── Output helpers ────────────────────────────────────────────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
_SEV_COLORS = {
    "critical": "\033[91m",  # bright red
    "high": "\033[31m",  # red
    "medium": "\033[33m",  # yellow
    "low": "\033[34m",  # blue
    "info": "\033[37m",  # grey
    "unknown": "\033[37m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _supports_color() -> bool:
    return sys.stdout.isatty()


def _color(text: str, sev: str) -> str:
    if not _supports_color():
        return text
    return f"{_SEV_COLORS.get(sev, '')}{text}{_RESET}"


def _print_table(report_dict: dict) -> None:
    """Print a compact table of findings to stdout."""
    summary = report_dict.get("summary", {})
    target = report_dict.get("target", "")

    print(f"\n{_BOLD}Target:{_RESET} {target}")
    print(f"{_BOLD}Total findings:{_RESET} {summary.get('total_findings', 0)}\n")

    # Severity summary bar
    sev_parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        count = summary.get("by_severity", {}).get(sev, 0)
        if count:
            sev_parts.append(_color(f"{count} {sev}", sev))
    if sev_parts:
        print("  " + "  ".join(sev_parts))
    print()

    col_w = {"sev": 10, "tool": 18, "file": 35, "line": 6, "title": 55}

    header = (
        f"{'Severity':<{col_w['sev']}}  "
        f"{'Tool':<{col_w['tool']}}  "
        f"{'File':<{col_w['file']}}  "
        f"{'Line':<{col_w['line']}}  "
        f"Title"
    )
    print(_BOLD + header + _RESET if _supports_color() else header)
    print("─" * (sum(col_w.values()) + 8))

    for result in report_dict.get("results", []):
        if not result.get("tool_available"):
            print(f"  ⚠  {result['tool']} — not installed")
            continue
        for f in result.get("findings", []):
            sev = f.get("severity", "unknown")
            file_short = Path(f.get("file", "")).name or f.get("file", "")
            if len(file_short) > col_w["file"]:
                file_short = "…" + file_short[-(col_w["file"] - 1) :]
            title = f.get("title", "")
            if len(title) > col_w["title"]:
                title = title[: col_w["title"] - 1] + "…"

            row = (
                f"{sev:<{col_w['sev']}}  "
                f"{result['tool']:<{col_w['tool']}}  "
                f"{file_short:<{col_w['file']}}  "
                f"{str(f.get('line', '')):<{col_w['line']}}  "
                f"{title}"
            )
            print(_color(row, sev))

    print()


def _should_fail(report_dict: dict, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    threshold = _SEV_ORDER.get(fail_on, 99)
    for result in report_dict.get("results", []):
        for f in result.get("findings", []):
            if _SEV_ORDER.get(f.get("severity", "unknown"), 99) <= threshold:
                return True
    return False


def _filter_severity(report_dict: dict, min_sev: str) -> dict:
    """Remove findings below min_sev from report dict."""
    threshold = _SEV_ORDER.get(min_sev, 99)
    import copy

    report = copy.deepcopy(report_dict)
    for result in report.get("results", []):
        result["findings"] = [
            f
            for f in result.get("findings", [])
            if _SEV_ORDER.get(f.get("severity", "unknown"), 99) <= threshold
        ]
    return report


def _emit(report_dict: dict, fmt: str, output_file: str | None, min_sev: str, fail_on: str) -> int:
    """Render the report and return the exit code."""
    filtered = _filter_severity(report_dict, min_sev)

    if fmt == "json":
        text = json.dumps(filtered, indent=2)
    elif fmt == "table":
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _print_table(filtered)
        text = buf.getvalue()
    else:
        text = format_markdown_report(filtered)

    if output_file:
        Path(output_file).write_text(text)
        print(f"Report written to: {output_file}", file=sys.stderr)
        if fmt == "table":
            _print_table(filtered)  # still show table on stdout
    else:
        if fmt == "table":
            _print_table(filtered)
        else:
            print(text)

    # Fail against the full report so --min-severity display filtering
    # cannot hide findings that should still fail CI.
    return 1 if _should_fail(report_dict, fail_on) else 0


# ── Scan runners ──────────────────────────────────────────────────────────────


async def _run_scan(args: argparse.Namespace) -> int:
    scan_type = args.scan_type
    timeout = args.timeout
    fmt = args.format
    tools = getattr(args, "tools", None)
    min_sev = getattr(args, "min_severity", "low")
    fail_on = getattr(args, "fail_on", "never")
    out_file = getattr(args, "output", None)

    print(f"Running {scan_type.upper()} scan on: {args.target}", file=sys.stderr)

    if scan_type == "sast":
        from argus.tools.sast import run_all_sast, run_bandit, run_eslint_security, run_semgrep

        if tools:
            tasks: list = []
            if "argus-languages" in tools or "native" in tools:
                from argus.tools.code import run_native_languages

                tasks.append(run_native_languages(args.target))
            if "semgrep" in tools:
                tasks.append(run_semgrep(args.target, config=args.semgrep_config, timeout=timeout))
            if "bandit" in tools:
                tasks.append(run_bandit(args.target, timeout=timeout))
            if "eslint" in tools:
                tasks.append(run_eslint_security(args.target, timeout=timeout))
            results = await asyncio.gather(*tasks)
        else:
            results = await run_all_sast(
                args.target, semgrep_config=args.semgrep_config, timeout=timeout
            )

    elif scan_type == "code":
        from argus.tools.code import run_native_languages

        results = [await run_native_languages(args.target)]

    elif scan_type == "sca":
        from argus.tools.sca import run_all_sca

        results = await run_all_sca(args.target, timeout=timeout)

    elif scan_type == "secrets":
        from argus.tools.secrets import run_all_secrets

        results = await run_all_secrets(args.target, timeout=timeout)

    elif scan_type == "iac":
        from argus.tools.iac import run_all_iac, run_checkov

        if getattr(args, "framework", None):
            results = [await run_checkov(args.target, framework=args.framework, timeout=timeout)]
        else:
            results = await run_all_iac(args.target, timeout=timeout)

    elif scan_type == "terraform":
        from argus.tools.terraform import run_all_terraform

        results = await run_all_terraform(args.target, timeout=timeout, tools=tools)

    elif scan_type == "ansible":
        from argus.tools.ansible import run_all_ansible

        results = await run_all_ansible(
            args.target,
            timeout=timeout,
            tools=tools,
            ansible_lint_profile=getattr(args, "profile", "safety"),
        )

    elif scan_type == "dast":
        from argus.tools.dast import run_all_dast

        results = await run_all_dast(args.target, timeout=max(timeout, 600))

    elif scan_type == "container":
        from argus.tools.iac import run_trivy_image

        results = [await run_trivy_image(args.target, timeout=timeout)]

    elif scan_type == "all":
        from argus.tools.dast import run_all_dast
        from argus.tools.iac import run_all_iac, run_trivy_image
        from argus.tools.sast import run_all_sast
        from argus.tools.sca import run_all_sca
        from argus.tools.secrets import run_all_secrets

        batches = await asyncio.gather(
            run_all_sast(args.target, timeout=timeout),
            run_all_sca(args.target, timeout=timeout),
            run_all_secrets(args.target, timeout=timeout),
            run_all_iac(args.target, timeout=timeout),
            return_exceptions=True,
        )
        results = [r for batch in batches if isinstance(batch, list) for r in batch]

        if getattr(args, "url", None):
            dast = await run_all_dast(args.url, timeout=600)
            results.extend(dast)
        if getattr(args, "image", None):
            ctr = await run_trivy_image(args.image, timeout=timeout)
            results.append(ctr)
    else:
        print(f"Unknown scan type: {scan_type}", file=sys.stderr)
        return 2

    report = AggregatedReport(target=args.target, results=list(results))
    report_dict = report.to_dict()

    total = report_dict["summary"]["total_findings"]
    unavailable = report_dict["summary"]["tools_unavailable"]
    print(f"Scan complete. {total} finding(s) found.", file=sys.stderr)
    if unavailable:
        print(f"Tools not installed (skipped): {', '.join(unavailable)}", file=sys.stderr)
        print("  Run 'argus tools' to see install instructions.", file=sys.stderr)

    return _emit(report_dict, fmt, out_file, min_sev, fail_on)


def _cmd_tools() -> None:
    """Print a table of all tools and their availability."""
    TOOLS = {
        # tool_name: (category, install_hint)
        "semgrep": ("SAST", "pip install semgrep"),
        "bandit": ("SAST (Python)", "pip install bandit"),
        "flake8": ("SAST (Python)", "pip install flake8 flake8-bandit"),
        "eslint": ("SAST (JS/TS)", "npm install -g eslint eslint-plugin-security"),
        "trivy": (
            "SCA / IaC / Container",
            "brew install trivy  OR  see aquasecurity.github.io/trivy",
        ),
        "safety": ("SCA (Python)", "pip install safety"),
        "pip-audit": ("SCA (Python)", "pip install pip-audit"),
        "npm": ("SCA (Node.js)", "Install Node.js from nodejs.org"),
        "gitleaks": ("Secrets", "brew install gitleaks"),
        "detect-secrets": ("Secrets", "pip install detect-secrets"),
        "trufflehog": ("Secrets", "brew install trufflehog"),
        "checkov": ("IaC / Terraform / Ansible", "pip install checkov"),
        "terrascan": ("IaC", "brew install terrascan"),
        "tfsec": ("Terraform", "brew install tfsec"),
        "tflint": ("Terraform", "brew install tflint"),
        "terraform": ("Terraform validate", "brew install terraform"),
        "kics": ("IaC / Terraform / Ansible", "brew install kics"),
        "ansible-lint": ("Ansible", "pip install ansible-lint"),
        "nikto": ("DAST", "brew install nikto"),
        "docker": ("DAST (ZAP) / Container", "Install Docker Desktop"),
    }

    use_color = _supports_color()
    green = "\033[32m" if use_color else ""
    red = "\033[31m" if use_color else ""
    reset = _RESET if use_color else ""
    bold = _BOLD if use_color else ""

    print(f"\n{bold}Built-in (always available){reset}\n")
    print(f"  {green}✔{reset}  {'argus-languages':<20} Multi-language code (Java, PHP, Terraform, Ansible, …)")
    print("       pip install argus-languages   or   argus scan code <path>")

    installed, missing = [], []
    for tool, (category, hint) in TOOLS.items():
        if is_tool_available(tool):
            installed.append((tool, category))
        else:
            missing.append((tool, category, hint))

    print(f"\n{bold}Installed ({len(installed)}/{len(TOOLS)}){reset}\n")
    for tool, cat in installed:
        print(f"  {green}✔{reset}  {tool:<20} {cat}")

    if missing:
        print(f"\n{bold}Not installed{reset}\n")
        for tool, cat, hint in missing:
            print(f"  {red}✘{reset}  {tool:<20} {cat}")
            print(f"       install: {hint}")

    print()


# ── Entry point ───────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        from argus import __version__

        print(f"argus-scan {__version__}")
        return 0

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "tools":
        _cmd_tools()
        return 0

    if args.command == "mcp":
        if getattr(args, "config", False):
            _print_mcp_config()
            return 0
        # Start the MCP server
        from argus.server import run as run_server

        run_server()
        return 0

    if args.command == "scan":
        if args.scan_type is None:
            parser.parse_args(["scan", "--help"])
            return 0
        return asyncio.run(_run_scan(args))

    parser.print_help()
    return 0


def _print_mcp_config() -> None:
    print(
        "{\n"
        '  "mcpServers": {\n'
        '    "argus": {\n'
        '      "command": "argus",\n'
        '      "args": ["mcp"]\n'
        "    }\n"
        "  }\n"
        "}"
    )


def run() -> None:
    """Synchronous entry point (called by pip-installed script)."""
    sys.exit(main())


def run_mcp() -> None:
    """Entry point for `argus-mcp` — start MCP server directly."""
    from argus.server import run as run_server

    run_server()


if __name__ == "__main__":
    sys.exit(main())
