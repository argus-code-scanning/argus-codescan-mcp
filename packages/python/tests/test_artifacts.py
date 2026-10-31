"""Private temp directory and --no-persist (#60)."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path

import pytest

from argus import cli
from argus.artifacts import private_temp_dir
from argus.tools import secrets


def test_private_temp_dir_redirects_and_cleans_up(tmp_path, monkeypatch):
    monkeypatch.setenv("TMPDIR", "/original/tmp")
    monkeypatch.delenv("TEMP", raising=False)
    before = tempfile.tempdir

    with private_temp_dir(tmp_path / "arts") as run_dir:
        assert run_dir.parent == tmp_path / "arts"
        if os.name != "nt":  # Windows has no POSIX mode bits; mkdtemp still limits access
            assert stat.S_IMODE(run_dir.stat().st_mode) == 0o700
        assert os.environ["TMPDIR"] == os.environ["TEMP"] == str(run_dir)
        assert tempfile.gettempdir() == str(run_dir)
        (run_dir / "leftover.json").write_text("{}")

    assert not run_dir.exists()
    assert list((tmp_path / "arts").iterdir()) == []
    assert os.environ["TMPDIR"] == "/original/tmp"
    assert "TEMP" not in os.environ
    assert tempfile.tempdir == before


def test_private_temp_dir_cleans_up_on_error(tmp_path):
    with pytest.raises(RuntimeError), private_temp_dir(tmp_path) as run_dir:
        (run_dir / "partial.json").write_text("{}")
        raise RuntimeError("scanner crashed")

    assert not run_dir.exists()


def test_no_persist_rejects_output(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["scan", "secrets", str(tmp_path), "--no-persist", "-o", str(tmp_path / "r.json")])

    assert exc.value.code == 2
    assert "--no-persist cannot be combined with --output" in capsys.readouterr().err


def test_no_persist_leaves_no_scanner_files(tmp_path, monkeypatch, capsys):
    """A gitleaks run (raw secrets in its report) plus a scanner's own stray temp file."""
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)
    target = tmp_path / "repo"
    target.mkdir()
    arts = tmp_path / "arts"
    seen: dict[str, str] = {}

    async def fake_run_command(cmd, cwd=None, timeout=300, env=None):
        report = Path(cmd[cmd.index("--report-path") + 1])
        report.write_text(json.dumps([{"RuleID": "aws-key", "File": "a.py", "Secret": "AKIA..."}]))
        stray = Path(os.environ["TMPDIR"]) / "gitleaks-cache.json"
        stray.write_text("raw scanner output")
        seen["report"], seen["stray"] = str(report), str(stray)
        return 0, "", ""

    monkeypatch.setattr(secrets, "is_tool_available", lambda name: name == "gitleaks")
    monkeypatch.setattr(secrets, "run_command", fake_run_command)

    code = cli.main(
        [
            "scan",
            "secrets",
            str(target),
            "--format",
            "json",
            "--no-persist",
            "--artifacts-dir",
            str(arts),
        ]
    )

    assert code == 0
    # Both files were written inside the private run directory...
    assert Path(seen["report"]).parent.parent == arts
    assert Path(seen["stray"]).parent.parent == arts
    # ...which is gone after the run, and the report still reached stdout.
    assert list(arts.iterdir()) == []
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["total_findings"] == 1
