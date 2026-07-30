"""Tests for scan file discovery and gitleaks portability."""

from __future__ import annotations

from pathlib import Path

from argus.utils import SKIP_SCAN_DIRS, find_scan_files


def test_find_scan_files_skips_node_modules(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n")
    node_modules = tmp_path / "node_modules" / "pkg"
    node_modules.mkdir(parents=True)
    (node_modules / "bad.py").write_text("AKIA1234567890123456\n")

    found = find_scan_files(tmp_path, "*.py")
    assert tmp_path / "app.py" in found
    assert node_modules / "bad.py" not in found


def test_find_scan_files_skips_venv(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("x = 1\n")
    venv_file = tmp_path / ".venv" / "lib" / "site.py"
    venv_file.parent.mkdir(parents=True)
    venv_file.write_text("secret\n")

    found = find_scan_files(tmp_path, "*.py")
    assert tmp_path / "main.py" in found
    assert venv_file not in found


def test_skip_scan_dirs_includes_common_junk() -> None:
    assert "node_modules" in SKIP_SCAN_DIRS
    assert ".venv" in SKIP_SCAN_DIRS
    assert "venv" in SKIP_SCAN_DIRS
