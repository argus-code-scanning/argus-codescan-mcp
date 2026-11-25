"""scripts/versions.py keeps every package version in sync (#11)."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "scripts" / "versions.py"
spec = importlib.util.spec_from_file_location("argus_versions_script", SCRIPT)
assert spec and spec.loader
versions = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = versions
spec.loader.exec_module(versions)

FILES = sorted(
    {loc.path for _, _, locs in versions.PACKAGES.values() for loc in locs} | {"README.md"}
)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    for rel in FILES:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / rel, tmp_path / rel)
    return tmp_path


def test_real_repository_is_in_sync() -> None:
    assert versions.problems(REPO) == []


def test_bump_updates_every_file_pin_and_readme(repo: Path, capsys) -> None:
    assert (
        versions.main(
            ["bump", "--scan", "0.11.0", "--languages", "0.9.0", "--npm", "0.13.0"], root=repo
        )
        == 0
    )
    assert versions.current(repo) == {
        "languages": "0.9.0",
        "scan": "0.11.0",
        "npm": "0.13.0",
        "vscode": versions.current(REPO)["vscode"],
    }
    assert '"argus-languages>=0.9.0"' in (repo / "packages/python/pyproject.toml").read_text(
        encoding="utf-8"
    )
    assert '__version__ = "0.11.0"' in (repo / "packages/python/src/argus/__init__.py").read_text(
        encoding="utf-8"
    )
    lock = json.loads((repo / "packages/npm/package-lock.json").read_text(encoding="utf-8"))
    assert lock["version"] == "0.13.0" and lock["packages"][""]["version"] == "0.13.0"
    readme = (repo / "README.md").read_text(encoding="utf-8")
    assert "`pip install argus-scan==0.11.0` (needs `argus-languages>=0.9.0`)" in readme
    assert versions.problems(repo) == []
    assert versions.main(["check"], root=repo) == 0
    capsys.readouterr()


@pytest.mark.parametrize(
    ("rel", "old", "new", "message"),
    [
        (
            "packages/python/src/argus/__init__.py",
            '__version__ = "',
            '__version__ = "9.9.9" #',
            "argus-scan: files disagree",
        ),
        (
            "packages/python/pyproject.toml",
            '"argus-languages>=',
            '"argus-languages>=0.0.1" #',
            "argus-scan requires argus-languages>=0.0.1",
        ),
        (
            "README.md",
            "| `argus-codescan` (npm) |",
            "| `argus-codescan` (npm) | 0.0.0 |",
            "README.md version table is out of date",
        ),
    ],
)
def test_check_reports_drift(
    repo: Path, rel: str, old: str, new: str, message: str, capsys
) -> None:
    path = repo / rel
    path.write_text(path.read_text(encoding="utf-8").replace(old, new, 1), encoding="utf-8")
    assert any(message in p for p in versions.problems(repo))
    assert versions.main(["check"], root=repo) == 1
    assert message in capsys.readouterr().err


def test_bump_rejects_bad_versions(repo: Path) -> None:
    with pytest.raises(SystemExit, match="not a version"):
        versions.main(["bump", "--scan", "latest"], root=repo)
