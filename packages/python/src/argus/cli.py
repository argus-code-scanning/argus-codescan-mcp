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
    argus scan ml /path/to/ml-project
    argus scan malware /path/to/project
    argus scan pci /path/to/project
    argus scan all /path/to/project
    argus scan dast http://localhost:3000
    argus scan container nginx:latest
    argus review .                 # local code review — git-changed files only
    argus review . --staged        # only staged files
    argus review . --base main     # changes vs main (+ local dirty files)
    argus tools        # list installed scanners
    argus mcp          # start MCP server (for AI clients)
    argus ci pr-paths --base <sha> --limit 50 -o scan-paths.txt
    argus ci pr-comment --sarif results/*.sarif -o comment.md
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from argus.models import AggregatedReport, ScanResult
from argus.utils import format_markdown_report, is_tool_available, refresh_report_summary

_CLASSIFICATIONS = {"pii", "phi", "pci", "confidential", "public", "unset"}


def _parse_classifications(value: str) -> str:
    tags = {tag.strip().lower() for tag in value.split(",") if tag.strip()}
    invalid = tags - _CLASSIFICATIONS
    if not tags or invalid:
        choices = ", ".join(sorted(_CLASSIFICATIONS))
        raise argparse.ArgumentTypeError(f"expected comma-separated classifications: {choices}")
    return ",".join(sorted(tags))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argus",
        description=(
            "Code security scanner — SAST, DAST, SCA, Secrets, IaC, Terraform, Ansible, ML/AI, Malware.\n"
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
    def _add_common(
        p: argparse.ArgumentParser,
        has_target: bool = True,
        paths_file: bool = True,
    ) -> None:
        if has_target:
            p.add_argument("target", help="Path to file, directory, URL, or image to scan")
        if paths_file:
            p.add_argument(
                "--paths-file",
                metavar="FILE",
                help=(
                    "Scan each path in FILE (one per line) instead of the whole target. "
                    "Blank lines and # comments are ignored. The target is still used "
                    "to discover .argus.yml."
                ),
            )
        p.add_argument(
            "--format",
            "-f",
            choices=["markdown", "json", "table", "sarif"],
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
            "--classification",
            metavar="TAGS",
            type=_parse_classifications,
            help=(
                "Only show findings with these comma-separated data classifications "
                "(pii, phi, pci, confidential, public, unset)"
            ),
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
        p.add_argument(
            "--upload",
            action="store_true",
            help="Upload results to Argus cloud dashboard (requires ARGUS_API_KEY)",
        )
        p.add_argument(
            "--no-upload",
            action="store_true",
            help="Skip cloud upload even when ARGUS_API_KEY is set",
        )
        p.add_argument(
            "--policy",
            metavar="FILE",
            help="Path to .argus.yml policy file (default: auto-discover from target)",
        )
        p.add_argument(
            "--baseline",
            metavar="FILE",
            help="Baseline scan JSON — only report new findings (overrides policy baseline)",
        )

    sast_p = scan_sub.add_parser("sast", help="Static Application Security Testing")
    _add_common(sast_p)
    sast_p.add_argument("--semgrep-config", default="auto", help="Semgrep ruleset (default: auto)")

    code_p = scan_sub.add_parser(
        "code",
        help="Built-in multi-language code scan (Java, PHP, Terraform, Ansible, … — no extra tools)",
    )
    _add_common(code_p)

    ml_p = scan_sub.add_parser(
        "ml",
        help="AI/ML security scan — unsafe model loading, LLM API keys, prompt injection (built-in)",
    )
    _add_common(ml_p)

    malware_p = scan_sub.add_parser(
        "malware",
        help="Malware / backdoor / crypto-miner / BAT-PS1 heuristics (built-in, not antivirus)",
    )
    _add_common(malware_p)

    pci_p = scan_sub.add_parser(
        "pci",
        help="PCI-DSS cardholder-data heuristics — CVV storage, PANs in logs, http:// card data (built-in)",
    )
    _add_common(pci_p)

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
    _add_common(dast_p, paths_file=False)

    ctr_p = scan_sub.add_parser("container", help="Container image vulnerability scan")
    _add_common(ctr_p, paths_file=False)

    all_p = scan_sub.add_parser("all", help="Run all applicable scans")
    _add_common(all_p)
    all_p.add_argument("--url", metavar="URL", help="Also run DAST against this URL")
    all_p.add_argument("--image", metavar="IMAGE", help="Also scan this container image")

    # ── compare ─────────────────────────────────────────────────────────────
    cmp_p = sub.add_parser("compare", help="Diff two scan JSON reports (baseline vs current)")
    cmp_p.add_argument("baseline", help="Path to baseline scan JSON")
    cmp_p.add_argument("current", help="Path to current scan JSON")
    cmp_p.add_argument(
        "--format",
        "-f",
        choices=["json", "markdown"],
        default="json",
        help="Output format (default: json)",
    )
    cmp_p.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Write output to FILE instead of stdout",
    )
    cmp_p.add_argument(
        "--fail-on-new",
        action="store_true",
        help="Exit 1 if any new findings exist vs baseline",
    )

    # ── ci ──────────────────────────────────────────────────────────────────
    ci_p = sub.add_parser("ci", help="Helpers for CI jobs")
    ci_sub = ci_p.add_subparsers(dest="ci_command", metavar="command")
    pr_paths_p = ci_sub.add_parser(
        "pr-paths",
        help="List changed files for a pull request scan (git diff), or fall back to a full scan",
    )
    pr_paths_p.add_argument(
        "--base", required=True, help="Base git revision (pull request base SHA)"
    )
    pr_paths_p.add_argument("--head", default="HEAD", help="Head git revision (default: HEAD)")
    pr_paths_p.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Fall back to a full scan when more than this many files changed (default: 50)",
    )
    pr_paths_p.add_argument(
        "--full-target",
        default=".",
        help="Path written when falling back to a full scan (default: .)",
    )
    pr_paths_p.add_argument(
        "--repo",
        default=".",
        help="Git repository root (default: .)",
    )
    pr_paths_p.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Write newline-separated scan paths to FILE",
    )
    pr_paths_p.add_argument(
        "--github-output",
        metavar="FILE",
        help="Append mode and changed_count to a GitHub Actions output file",
    )
    pr_comment_p = ci_sub.add_parser(
        "pr-comment",
        help="Build the pull request comment (summary table + top fix suggestions) from SARIF",
    )
    pr_comment_p.add_argument(
        "--sarif",
        nargs="+",
        required=True,
        metavar="FILE",
        help="Argus SARIF files to summarise (missing files are noted in the comment)",
    )
    pr_comment_p.add_argument(
        "--scope-mode",
        choices=["changed", "full", "empty"],
        help="Scan scope from 'argus ci pr-paths' (mode output)",
    )
    pr_comment_p.add_argument(
        "--changed-count",
        type=_optional_int,
        help="Number of changed files from 'argus ci pr-paths'",
    )
    pr_comment_p.add_argument("--run-url", help="Link to the CI run")
    pr_comment_p.add_argument(
        "--dashboard-url",
        help="Link to the cloud dashboard run (default: $ARGUS_DASHBOARD_URL)",
    )
    pr_comment_p.add_argument(
        "--max-suggestions",
        type=int,
        default=5,
        help="Number of fix suggestions to list (default: 5)",
    )
    pr_comment_p.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Write the comment Markdown to FILE instead of stdout",
    )

    # ── review (local code review — changed files only) ─────────────────────
    review_p = sub.add_parser(
        "review",
        help="Local code review — scan only git-changed (or staged) files",
    )
    review_p.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Git repository path (default: current directory)",
    )
    _add_common(review_p, has_target=False, paths_file=False)
    review_p.add_argument(
        "--staged",
        action="store_true",
        help="Only review staged files (git diff --cached)",
    )
    review_p.add_argument(
        "--base",
        metavar="REF",
        help="Review changes vs REF (e.g. main, origin/main) plus local dirty files",
    )
    review_p.add_argument(
        "--semgrep-config",
        default="auto",
        help="Semgrep ruleset for the review SAST pass (default: auto)",
    )

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


def _filter_classification(report_dict: dict, classifications: str | None) -> dict:
    """Keep findings matching any requested data classification."""
    if not classifications:
        return report_dict
    allowed = {tag.strip().lower() for tag in classifications.split(",") if tag.strip()}
    import copy

    report = copy.deepcopy(report_dict)
    for result in report.get("results", []):
        result["findings"] = [
            finding
            for finding in result.get("findings", [])
            if str(finding.get("data_classification", "unset")).lower() in allowed
        ]
    return report


def _emit(
    report_dict: dict,
    fmt: str,
    output_file: str | None,
    min_sev: str,
    fail_on: str,
    classification: str | None = None,
) -> int:
    """Render the report and return the exit code."""
    from argus.formatters.sarif import aggregated_report_to_sarif

    filtered = _filter_classification(_filter_severity(report_dict, min_sev), classification)
    refresh_report_summary(filtered)

    if fmt == "json":
        text = json.dumps(filtered, indent=2)
    elif fmt == "sarif":
        text = json.dumps(aggregated_report_to_sarif(filtered), indent=2)
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


async def _dispatch_scan(
    scan_type: str,
    target: str,
    timeout: int,
    tools: list[str] | None,
    semgrep_cfg: str,
    args: argparse.Namespace,
) -> list[ScanResult] | None:
    """Run one scan type against a single target. Returns None for an unknown type."""
    if scan_type == "sast":
        from argus.tools.sast import run_all_sast, run_bandit, run_eslint_security, run_semgrep

        if tools:
            tasks: list = []
            if "argus-languages" in tools or "native" in tools:
                from argus.tools.code import run_native_languages

                tasks.append(run_native_languages(target))
            if "semgrep" in tools:
                tasks.append(run_semgrep(target, config=semgrep_cfg, timeout=timeout))
            if "bandit" in tools:
                tasks.append(run_bandit(target, timeout=timeout))
            if "eslint" in tools:
                tasks.append(run_eslint_security(target, timeout=timeout))
            return list(await asyncio.gather(*tasks))
        return await run_all_sast(target, semgrep_config=semgrep_cfg, timeout=timeout)

    if scan_type == "code":
        from argus.tools.code import run_native_languages

        return [await run_native_languages(target)]

    if scan_type == "ml":
        from argus.tools.ml import run_ml_scan

        return [await run_ml_scan(target)]

    if scan_type == "malware":
        from argus.tools.malware import run_malware_scan

        return [await run_malware_scan(target)]

    if scan_type == "pci":
        from argus.tools.pci import run_pci_scan

        return [await run_pci_scan(target)]

    if scan_type == "sca":
        from argus.tools.sca import run_all_sca

        return await run_all_sca(target, timeout=timeout)

    if scan_type == "secrets":
        from argus.tools.secrets import run_all_secrets

        return await run_all_secrets(target, timeout=timeout)

    if scan_type == "iac":
        from argus.tools.iac import run_all_iac, run_checkov

        if getattr(args, "framework", None):
            return [await run_checkov(target, framework=args.framework, timeout=timeout)]
        return await run_all_iac(target, timeout=timeout)

    if scan_type == "terraform":
        from argus.tools.terraform import run_all_terraform

        return await run_all_terraform(target, timeout=timeout, tools=tools)

    if scan_type == "ansible":
        from argus.tools.ansible import run_all_ansible

        return await run_all_ansible(
            target,
            timeout=timeout,
            tools=tools,
            ansible_lint_profile=getattr(args, "profile", "safety"),
        )

    if scan_type == "dast":
        from argus.tools.dast import run_all_dast

        return await run_all_dast(target, timeout=max(timeout, 600))

    if scan_type == "container":
        from argus.tools.iac import run_trivy_image

        return [await run_trivy_image(target, timeout=timeout)]

    if scan_type == "all":
        from argus.tools.iac import run_all_iac
        from argus.tools.malware import run_malware_scan
        from argus.tools.ml import run_ml_scan
        from argus.tools.sast import run_all_sast
        from argus.tools.sca import run_all_sca
        from argus.tools.secrets import run_all_secrets

        batches = await asyncio.gather(
            run_all_sast(target, timeout=timeout),
            run_all_sca(target, timeout=timeout),
            run_all_secrets(target, timeout=timeout),
            run_all_iac(target, timeout=timeout),
            run_ml_scan(target),
            run_malware_scan(target),
            return_exceptions=True,
        )
        results: list[ScanResult] = []
        for batch in batches:
            if isinstance(batch, list):
                results.extend(batch)
            elif not isinstance(batch, BaseException):
                results.append(batch)
        return results

    return None


async def _run_scan(args: argparse.Namespace) -> int:
    from argus.cloud_upload import ScanTimer, is_cloud_upload_enabled, upload_scan_report
    from argus.compare import compare_reports, report_from_new_findings_only
    from argus.policy import apply_policy, load_policy, merge_cli_policy

    scan_type = args.scan_type
    timer = ScanTimer()
    timeout = args.timeout
    fmt = args.format
    tools = getattr(args, "tools", None)
    min_sev = getattr(args, "min_severity", "low")
    fail_on = getattr(args, "fail_on", "never")
    out_file = getattr(args, "output", None)

    policy = load_policy(path=getattr(args, "policy", None), start=args.target)
    policy = merge_cli_policy(
        policy,
        fail_on=fail_on if fail_on != "never" else None,
        min_severity=min_sev if min_sev != "low" else None,
        tools=tools,
        semgrep_config=getattr(args, "semgrep_config", None),
    )
    if policy.fail_on != "never":
        fail_on = policy.fail_on
    if policy.min_severity != "low":
        min_sev = policy.min_severity
    if policy.tools and not tools:
        tools = policy.tools
    semgrep_cfg = getattr(args, "semgrep_config", "auto")
    if policy.semgrep_config != "auto":
        semgrep_cfg = policy.semgrep_config

    from argus.pr_scan import merge_results_by_tool, read_paths_file

    paths_file = getattr(args, "paths_file", None)
    if paths_file:
        try:
            paths = read_paths_file(Path(paths_file))
        except FileNotFoundError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        report_target = f"{args.target} ({len(paths)} path(s))"
        print(
            f"Running {scan_type.upper()} scan on {len(paths)} path(s) from {paths_file}",
            file=sys.stderr,
        )
    else:
        paths = [args.target]
        report_target = args.target
        print(f"Running {scan_type.upper()} scan on: {args.target}", file=sys.stderr)

    results: list[ScanResult] = []
    for path in paths:
        batch = await _dispatch_scan(scan_type, path, timeout, tools, semgrep_cfg, args)
        if batch is None:
            print(f"Unknown scan type: {scan_type}", file=sys.stderr)
            return 2
        results.extend(batch)

    if paths_file:
        results = merge_results_by_tool(results)

    if scan_type == "all":
        from argus.tools.dast import run_all_dast
        from argus.tools.iac import run_trivy_image

        if getattr(args, "url", None):
            results.extend(await run_all_dast(args.url, timeout=600))
        if getattr(args, "image", None):
            results.append(await run_trivy_image(args.image, timeout=timeout))

    report = AggregatedReport(target=report_target, results=results)
    report_dict = apply_policy(report.to_dict(), policy)

    baseline_path = getattr(args, "baseline", None) or policy.baseline
    if baseline_path:
        baseline_data = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
        diff = compare_reports(baseline_data, report_dict)
        print(
            f"Baseline diff: {diff['summary']['new']} new, "
            f"{diff['summary']['fixed']} fixed, "
            f"{diff['summary']['unchanged']} unchanged.",
            file=sys.stderr,
        )
        if policy.fail_on_new_only:
            report_dict = report_from_new_findings_only(report_dict, baseline_data)
            fail_on = fail_on if fail_on != "never" else "low"

    total = sum(len(r.get("findings", [])) for r in report_dict.get("results", []))
    unavailable = report_dict["summary"]["tools_unavailable"]
    print(f"Scan complete. {total} finding(s) found.", file=sys.stderr)
    if unavailable:
        print(f"Tools not installed (skipped): {', '.join(unavailable)}", file=sys.stderr)
        print("  Run 'argus tools' to see install instructions.", file=sys.stderr)

    should_upload = (getattr(args, "upload", False) or is_cloud_upload_enabled()) and not getattr(
        args, "no_upload", False
    )
    if should_upload:
        try:
            upload_fail_on = fail_on if fail_on != "never" else None
            status = await upload_scan_report(
                report_dict,
                duration_sec=timer.elapsed,
                fail_on=upload_fail_on,
                scan_type=scan_type,
                target=args.target,
                force=getattr(args, "upload", False),
            )
            if status:
                print(f"Cloud upload: {status}", file=sys.stderr)
        except Exception as exc:
            print(f"Cloud upload failed: {exc}", file=sys.stderr)

    return _emit(report_dict, fmt, out_file, min_sev, fail_on, getattr(args, "classification", None))


def _cmd_pr_paths(args: argparse.Namespace) -> int:
    import subprocess

    from argus.pr_scan import format_scope, resolve_pr_scan_scope, write_github_output

    repo = Path(args.repo)
    try:
        scope = resolve_pr_scan_scope(
            repo,
            args.base,
            args.head,
            limit=args.limit,
            full_target=args.full_target,
        )
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode(errors="replace").strip() if exc.stderr else str(exc)
        print(f"git diff failed: {detail}", file=sys.stderr)
        return 2

    sys.stdout.write(format_scope(scope))
    if args.output:
        body = "\n".join(scope.paths)
        if body:
            body += "\n"
        Path(args.output).write_text(body, encoding="utf-8")
    if args.github_output:
        write_github_output(Path(args.github_output), scope)
    return 0


def _optional_int(value: str) -> int | None:
    """argparse type that treats an empty string (unset CI output) as None."""
    return int(value) if value.strip() else None


def _cmd_pr_comment(args: argparse.Namespace) -> int:
    import os

    from argus.pr_comment import build_pr_comment, load_sarif_reports

    try:
        report, missing = load_sarif_reports([Path(p) for p in args.sarif])
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"Could not read SARIF: {exc}", file=sys.stderr)
        return 2
    for name in missing:
        print(f"SARIF file not found (skipped): {name}", file=sys.stderr)

    body = build_pr_comment(
        report,
        scope_mode=args.scope_mode,
        changed_count=args.changed_count,
        run_url=args.run_url,
        dashboard_url=args.dashboard_url or os.environ.get("ARGUS_DASHBOARD_URL", "").strip(),
        missing_reports=missing,
        max_suggestions=args.max_suggestions,
    )
    if args.output:
        Path(args.output).write_text(body, encoding="utf-8")
        print(f"PR comment written to: {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(body)
    return 0


async def _run_review(args: argparse.Namespace) -> int:
    """Local code review: secrets + SAST + malware on git-changed files only."""
    from argus.cloud_upload import ScanTimer, is_cloud_upload_enabled, upload_scan_report
    from argus.compare import compare_reports, report_from_new_findings_only
    from argus.policy import apply_policy, load_policy, merge_cli_policy
    from argus.tools.review import review_summary_lines, run_review

    timer = ScanTimer()
    timeout = args.timeout
    fmt = args.format
    tools = getattr(args, "tools", None)
    min_sev = getattr(args, "min_severity", "low")
    fail_on = getattr(args, "fail_on", "never")
    out_file = getattr(args, "output", None)
    staged = bool(getattr(args, "staged", False))
    base = getattr(args, "base", None)

    policy = load_policy(path=getattr(args, "policy", None), start=args.target)
    policy = merge_cli_policy(
        policy,
        fail_on=fail_on if fail_on != "never" else None,
        min_severity=min_sev if min_sev != "low" else None,
        tools=tools,
        semgrep_config=getattr(args, "semgrep_config", None),
    )
    if policy.fail_on != "never":
        fail_on = policy.fail_on
    if policy.min_severity != "low":
        min_sev = policy.min_severity
    semgrep_cfg = getattr(args, "semgrep_config", "auto")
    if policy.semgrep_config != "auto":
        semgrep_cfg = policy.semgrep_config

    mode = "staged" if staged else (f"base={base}" if base else "vs HEAD")
    print(f"Running local REVIEW ({mode}) on: {args.target}", file=sys.stderr)

    report = await run_review(
        args.target,
        staged=staged,
        base=base,
        timeout=timeout,
        semgrep_config=semgrep_cfg,
    )
    for line in review_summary_lines(report):
        print(line, file=sys.stderr)

    report_dict = apply_policy(report.to_dict(), policy)

    baseline_path = getattr(args, "baseline", None) or policy.baseline
    if baseline_path:
        baseline_data = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
        diff = compare_reports(baseline_data, report_dict)
        print(
            f"Baseline diff: {diff['summary']['new']} new, "
            f"{diff['summary']['fixed']} fixed, "
            f"{diff['summary']['unchanged']} unchanged.",
            file=sys.stderr,
        )
        if policy.fail_on_new_only:
            report_dict = report_from_new_findings_only(report_dict, baseline_data)
            fail_on = fail_on if fail_on != "never" else "low"

    total = sum(len(r.get("findings", [])) for r in report_dict.get("results", []))
    unavailable = report_dict["summary"]["tools_unavailable"]
    print(f"Review complete. {total} finding(s) found.", file=sys.stderr)
    if unavailable:
        print(f"Tools not installed (skipped): {', '.join(unavailable)}", file=sys.stderr)
        print("  Run 'argus tools' to see install instructions.", file=sys.stderr)

    should_upload = (getattr(args, "upload", False) or is_cloud_upload_enabled()) and not getattr(
        args, "no_upload", False
    )
    if should_upload:
        try:
            upload_fail_on = fail_on if fail_on != "never" else None
            status = await upload_scan_report(
                report_dict,
                duration_sec=timer.elapsed,
                fail_on=upload_fail_on,
                scan_type="review",
                target=args.target,
                force=getattr(args, "upload", False),
            )
            if status:
                print(f"Cloud upload: {status}", file=sys.stderr)
        except Exception as exc:
            print(f"Cloud upload failed: {exc}", file=sys.stderr)

    return _emit(report_dict, fmt, out_file, min_sev, fail_on, getattr(args, "classification", None))


def _cmd_compare(args: argparse.Namespace) -> int:
    from argus.compare import compare_reports

    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    current = json.loads(Path(args.current).read_text(encoding="utf-8"))
    diff = compare_reports(baseline, current)

    if args.format == "markdown":
        lines = [
            "# Scan Comparison",
            "",
            f"- **New findings:** {diff['summary']['new']}",
            f"- **Fixed:** {diff['summary']['fixed']}",
            f"- **Unchanged:** {diff['summary']['unchanged']}",
            "",
        ]
        if diff["new"]:
            lines.append("## New findings")
            for f in diff["new"]:
                lines.append(
                    f"- [{f.get('severity')}] {f.get('tool')}: {f.get('title')} "
                    f"({f.get('file')}:{f.get('line', 0)})"
                )
        text = "\n".join(lines)
    else:
        text = json.dumps(diff, indent=2)

    if args.output:
        Path(args.output).write_text(text)
        print(f"Comparison written to: {args.output}", file=sys.stderr)
    else:
        print(text)

    if getattr(args, "fail_on_new", False) and diff["summary"]["new"] > 0:
        return 1
    return 0


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
        "govulncheck": ("SCA (Go)", "go install golang.org/x/vuln/cmd/govulncheck@latest"),
        "composer": ("SCA (PHP)", "brew install composer  OR  see getcomposer.org"),
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
    print(
        f"  {green}✔{reset}  {'argus-languages':<20} Multi-language code (Java, PHP, Terraform, Ansible, …)"
    )
    print("       pip install argus-languages   or   argus scan code <path>")
    print(
        f"  {green}✔{reset}  {'argus-ml':<20} AI/ML & LLM pipeline security (model load, API keys, prompts)"
    )
    print("       argus scan ml <path>   (included in argus scan all)")

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

    if args.command == "ci":
        if getattr(args, "ci_command", None) is None:
            parser.parse_args(["ci", "--help"])
            return 0
        if args.ci_command == "pr-paths":
            return _cmd_pr_paths(args)
        if args.ci_command == "pr-comment":
            return _cmd_pr_comment(args)
        print(f"Unknown ci command: {args.ci_command}", file=sys.stderr)
        return 2

    if args.command == "compare":
        return _cmd_compare(args)

    if args.command == "review":
        return asyncio.run(_run_review(args))

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
        '      "args": ["mcp"],\n'
        '      "env": {\n'
        '        "ARGUS_API_URL": "http://localhost:4000/v1",\n'
        '        "ARGUS_API_KEY": "arg_live_PASTE_YOUR_KEY"\n'
        "      }\n"
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
