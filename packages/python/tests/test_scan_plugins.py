"""Scan plugins via the argus.scan_plugins entry point group (#238)."""

from __future__ import annotations

import argparse
import json
from typing import Any

import pytest

from argus import cli, plugins
from argus.models import Finding, ScanResult, ScanType, Severity


class FakePlugin:
    name = "fake"
    help = "Fake plugin scan"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--level", default="high")

    async def run(self, target: str, args: argparse.Namespace, timeout: int) -> list[ScanResult]:
        result = ScanResult(tool="argus-fake", scan_type=ScanType.IAC, target=target)
        result.findings.append(
            Finding(
                title="Fake issue",
                severity=Severity(args.level),
                scan_type=ScanType.IAC,
                tool="argus-fake",
                file="fake.conf",
                line=3,
                rule_id="fake-rule",
            )
        )
        return [result]


class EntryPoint:
    def __init__(self, name: str, obj: Any) -> None:
        self.name = name
        self._obj = obj

    def load(self) -> Any:
        if isinstance(self._obj, Exception):
            raise self._obj
        return self._obj


@pytest.fixture
def installed(monkeypatch: pytest.MonkeyPatch):
    def install(*eps: EntryPoint) -> None:
        monkeypatch.setattr(plugins, "entry_points", lambda group: list(eps))
        plugins.load_scan_plugins.cache_clear()

    yield install
    plugins.load_scan_plugins.cache_clear()


def test_plugin_adds_scan_subcommand_and_runs(installed, tmp_path, capsys) -> None:
    installed(EntryPoint("fake", FakePlugin))  # a class is instantiated
    code = cli.main(
        [
            "scan",
            "fake",
            str(tmp_path),
            "--format",
            "json",
            "--level",
            "medium",
            "--fail-on",
            "medium",
        ]
    )
    out = json.loads(capsys.readouterr().out)
    findings = [f for r in out["results"] for f in r["findings"]]
    assert [f["rule_id"] for f in findings] == ["fake-rule"]
    assert findings[0]["severity"] == "medium"
    assert code == 1  # --fail-on applies to plugin findings


def test_broken_and_invalid_plugins_are_skipped(installed, capsys) -> None:
    installed(EntryPoint("boom", RuntimeError("import failed")), EntryPoint("odd", object()))
    assert plugins.load_scan_plugins() == {}
    err = capsys.readouterr().err
    assert "could not load scan plugin 'boom'" in err
    assert "'odd' is missing" in err


def test_plugin_cannot_replace_builtin_scan(installed, capsys) -> None:
    class Sast(FakePlugin):
        name = "sast"

    installed(EntryPoint("sast", Sast()))
    parser = cli.build_parser()
    assert "clashes with a built-in" in capsys.readouterr().err
    args = parser.parse_args(["scan", "sast", "."])
    assert args.scan_type == "sast"


def test_no_plugins_installed(installed) -> None:
    installed()
    assert plugins.load_scan_plugins() == {}
    cli.build_parser()  # still builds
