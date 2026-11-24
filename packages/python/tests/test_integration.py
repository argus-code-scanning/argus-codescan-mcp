"""Integration tests for the CLI, the MCP server and CI behaviour (#12).

These run the real entry points (``argus`` CLI ``main`` and the MCP server over stdio) with
external scanners mocked or not needed, so they work on any machine and in CI.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import pytest

from argus import cli
from argus.models import Finding, ScanResult, ScanType, Severity
from argus.utils import collect_scan_results

COMMAND_INJECTION = "import subprocess\n\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n"


def _result(tool: str, severity: Severity | None = None) -> ScanResult:
    result = ScanResult(tool=tool, scan_type=ScanType.SAST, target=".")
    if severity is not None:
        result.findings.append(
            Finding(
                title=f"{tool} finding",
                severity=severity,
                scan_type=ScanType.SAST,
                tool=tool,
                file="app.py",
                line=1,
                rule_id=f"{tool}-rule",
            )
        )
    return result


# --- argus tools ---------------------------------------------------------------------------


def test_argus_tools_lists_builtin_installed_and_missing(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "is_tool_available", lambda name: name in {"semgrep", "gitleaks"})
    monkeypatch.setenv("NO_COLOR", "1")
    assert cli.main(["tools"]) == 0
    out = capsys.readouterr().out
    assert "Built-in (always available)" in out
    assert "argus-languages" in out
    assert "Installed (2/" in out
    assert "Not installed" in out
    assert "install: brew install trivy" in out or "trivy" in out


# --- --fail-on uses the full report ---------------------------------------------------------


def test_fail_on_counts_findings_hidden_by_min_severity(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text(COMMAND_INJECTION)
    code = cli.main(
        [
            "scan",
            "code",
            str(tmp_path),
            "--format",
            "json",
            "--min-severity",
            "critical",
            "--fail-on",
            "high",
        ]
    )
    shown = json.loads(capsys.readouterr().out)
    severities = [f["severity"] for r in shown["results"] for f in r["findings"]]
    assert "high" not in severities  # hidden from the output by --min-severity
    assert code == 1  # ...but still fails the build


def test_policy_file_min_severity_hides_but_still_fails(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text(COMMAND_INJECTION)
    (tmp_path / ".argus.yml").write_text("min_severity: critical\nfail_on: high\n")
    code = cli.main(["scan", "code", str(tmp_path), "--format", "json"])
    shown = json.loads(capsys.readouterr().out)
    assert not [f for r in shown["results"] for f in r["findings"]]
    assert code == 1


def test_fail_on_never_and_clean_project_exit_zero(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text(COMMAND_INJECTION)
    assert cli.main(["scan", "code", str(tmp_path), "--format", "json", "--fail-on", "never"]) == 0
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "app.py").write_text("def add(a, b):\n    return a + b\n")
    assert cli.main(["scan", "code", str(clean), "--format", "json", "--fail-on", "low"]) == 0
    capsys.readouterr()


# --- collect_scan_results ---------------------------------------------------------------------


def test_collect_scan_results_drops_and_logs_exceptions(caplog) -> None:
    ok = _result("semgrep")
    with caplog.at_level(logging.ERROR):
        out = collect_scan_results(
            [ok, RuntimeError("trivy crashed"), _result("bandit")], label="SAST"
        )
    assert [r.tool for r in out] == ["semgrep", "bandit"]
    assert "trivy crashed" in caplog.text


# --- argus scan all with mocked scanners ------------------------------------------------------


def test_scan_all_merges_results_and_survives_a_crashing_scanner(
    monkeypatch, tmp_path, capsys
) -> None:
    import argus.tools.iac as iac
    import argus.tools.malware as malware
    import argus.tools.ml as ml
    import argus.tools.sast as sast
    import argus.tools.sca as sca
    import argus.tools.secrets as secrets

    async def sast_all(target, **_):
        return [_result("semgrep", Severity.HIGH), _result("bandit")]

    async def sca_all(target, **_):
        return [_result("pip-audit", Severity.MEDIUM)]

    async def secrets_all(target, **_):
        raise RuntimeError("gitleaks exploded")

    async def iac_all(target, **_):
        return []

    async def one(target, **_):
        return _result("argus-ml")

    async def mal(target, **_):
        return _result("argus-malware", Severity.CRITICAL)

    monkeypatch.setattr(sast, "run_all_sast", sast_all)
    monkeypatch.setattr(sca, "run_all_sca", sca_all)
    monkeypatch.setattr(secrets, "run_all_secrets", secrets_all)
    monkeypatch.setattr(iac, "run_all_iac", iac_all)
    monkeypatch.setattr(ml, "run_ml_scan", one)
    monkeypatch.setattr(malware, "run_malware_scan", mal)

    code = cli.main(
        ["scan", "all", str(tmp_path), "--format", "json", "--fail-on", "critical", "--no-upload"]
    )
    report = json.loads(capsys.readouterr().out)
    tools = {r["tool"] for r in report["results"]}
    assert {"semgrep", "bandit", "pip-audit", "argus-ml", "argus-malware"} <= tools
    assert "gitleaks" not in tools  # the crashing scanner is dropped, the scan goes on
    severities = sorted(f["severity"] for r in report["results"] for f in r["findings"])
    assert severities == ["critical", "high", "medium"]
    assert code == 1


# --- MCP server over stdio --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mcp_server_initializes_lists_tools_and_runs_one(tmp_path: Path) -> None:
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    (tmp_path / "train.py").write_text("import torch\nmodel = torch.load(path)\n")
    params = StdioServerParameters(command=sys.executable, args=["-m", "argus.server"])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()
        assert init.serverInfo.name == "argus-scan"
        assert init.capabilities.tools is not None

        names = {t.name for t in (await session.list_tools()).tools}
        assert {"scan_all", "scan_sast", "apply_fix", "check_tools"} <= names

        tools = await session.call_tool("check_tools", {})
        assert not tools.isError
        assert "Security Tool Availability" in tools.content[0].text

        ml = await session.call_tool("scan_ml", {"target": str(tmp_path)})
        assert not ml.isError
        assert "torch.load" in ml.content[0].text or "pickle" in ml.content[0].text.lower()
