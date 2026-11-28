"""Tests for pull-request changed-file scan selection."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from argus.cli import main
from argus.models import Finding, ScanResult, ScanType, Severity
from argus.pr_scan import (
    merge_results_by_tool,
    read_paths_file,
    rebase_finding_paths,
    resolve_pr_scan_scope,
    select_scan_scope,
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=Test",
            *args,
        ],
        check=True,
        capture_output=True,
    )


def _commit_all(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)


def _rev(repo: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        text=True,
    ).strip()


def test_select_scan_scope_lists_existing_files(tmp_path: Path) -> None:
    (tmp_path / "kept.py").write_text("x = 1\n")
    scope = select_scan_scope(
        ["kept.py", "deleted.py", "kept.py"],
        limit=50,
        repo_root=tmp_path,
    )
    assert scope.mode == "changed"
    assert scope.paths == ("kept.py",)
    assert scope.changed_count == 2


def test_select_scan_scope_falls_back_when_over_limit(tmp_path: Path) -> None:
    scope = select_scan_scope(
        ["a.py", "b.py", "c.py"],
        limit=2,
        full_target=".",
        repo_root=tmp_path,
    )
    assert scope.mode == "full"
    assert scope.paths == (".",)
    assert scope.changed_count == 3


def test_select_scan_scope_empty_when_only_deletions(tmp_path: Path) -> None:
    scope = select_scan_scope(["gone.py"], limit=50, repo_root=tmp_path)
    assert scope.mode == "empty"
    assert scope.paths == ()
    assert scope.changed_count == 1


def test_read_paths_file_skips_comments_and_duplicates(tmp_path: Path) -> None:
    path = tmp_path / "paths.txt"
    path.write_text("# comment\n\na.py\na.py\n  b.py  \n")
    assert read_paths_file(path) == ["a.py", "b.py"]


def test_merge_results_by_tool_dedupes_errors() -> None:
    def result(title: str) -> ScanResult:
        scan = ScanResult(
            tool="gitleaks",
            scan_type=ScanType.SECRETS,
            target="a.py",
            tool_available=False,
            errors=["gitleaks is not installed"],
        )
        scan.findings.append(
            Finding(
                title=title,
                severity=Severity.HIGH,
                scan_type=ScanType.SECRETS,
                tool="gitleaks",
            )
        )
        return scan

    merged = merge_results_by_tool([result("one"), result("two")])
    assert len(merged) == 1
    assert [f.title for f in merged[0].findings] == ["one", "two"]
    assert merged[0].errors == ["gitleaks is not installed"]


def test_git_diff_lists_changed_files_and_skips_deletions(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    (tmp_path / "a.py").write_text("print(1)\n")
    (tmp_path / "old.py").write_text("print(4)\n")
    _commit_all(tmp_path, "init")
    base = _rev(tmp_path)

    (tmp_path / "a.py").write_text("print(2)\n")
    (tmp_path / "b.py").write_text("print(3)\n")
    (tmp_path / "old.py").rename(tmp_path / "new.py")
    (tmp_path / "gone.py").write_text("print(5)\n")
    _commit_all(tmp_path, "edit")
    (tmp_path / "gone.py").unlink()
    _commit_all(tmp_path, "delete")

    scope = resolve_pr_scan_scope(tmp_path, base, "HEAD", limit=50)
    assert scope.mode == "changed"
    assert set(scope.paths) == {"a.py", "b.py", "new.py"}
    assert "gone.py" not in scope.paths
    assert "old.py" not in scope.paths


def test_git_diff_falls_back_over_limit(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    (tmp_path / "base.txt").write_text("base\n")
    _commit_all(tmp_path, "init")
    base = _rev(tmp_path)
    (tmp_path / "one.txt").write_text("1\n")
    (tmp_path / "two.txt").write_text("2\n")
    _commit_all(tmp_path, "two files")

    scope = resolve_pr_scan_scope(tmp_path, base, "HEAD", limit=1, full_target=".")
    assert scope.mode == "full"
    assert scope.paths == (".",)
    assert scope.changed_count == 2


def test_pr_paths_cli_writes_github_output(tmp_path: Path, capsys) -> None:
    _git(tmp_path, "init")
    (tmp_path / "keep.py").write_text("x = 1\n")
    _commit_all(tmp_path, "init")
    base = _rev(tmp_path)
    (tmp_path / "keep.py").write_text("x = 2\n")
    _commit_all(tmp_path, "edit")

    out = tmp_path / "scan-paths.txt"
    gh_out = tmp_path / "github.txt"
    code = main(
        [
            "ci",
            "pr-paths",
            "--repo",
            str(tmp_path),
            "--base",
            base,
            "--limit",
            "50",
            "--output",
            str(out),
            "--github-output",
            str(gh_out),
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["mode"] == "changed"
    assert payload["paths"] == ["keep.py"]
    assert out.read_text(encoding="utf-8") == "keep.py\n"
    assert "mode=changed" in gh_out.read_text(encoding="utf-8")
    assert "changed_count=1" in gh_out.read_text(encoding="utf-8")


def test_paths_file_scans_only_listed_files(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "hit.py").write_text("eval(user)\n")
    (tmp_path / "miss.py").write_text("eval(other)\n")
    paths = tmp_path / "paths.txt"
    paths.write_text("hit.py\n# skip\n")
    report = tmp_path / "report.json"

    code = main(
        [
            "scan",
            "code",
            ".",
            "--paths-file",
            str(paths),
            "--format",
            "json",
            "--output",
            str(report),
            "--fail-on",
            "never",
        ]
    )
    assert code == 0
    data = json.loads(report.read_text(encoding="utf-8"))
    files = [finding["file"] for result in data["results"] for finding in result["findings"]]
    assert any(path.endswith("hit.py") for path in files)
    assert not any(path.endswith("miss.py") for path in files)


def _finding(file: str) -> Finding:
    return Finding(
        title="t", severity=Severity.HIGH, scan_type=ScanType.SAST, tool="x", file=file, line=1
    )


def test_rebase_finding_paths_to_repository_root(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src" / "app").mkdir(parents=True)
    (tmp_path / "src" / "app" / "server.py").write_text("x\n")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("x\n")
    results = [
        ScanResult(
            tool="x",
            scan_type=ScanType.SAST,
            target="src/app/server.py",
            findings=[
                _finding("server.py"),  # bare name from a one-file scan
                _finding(str(tmp_path / "src" / "app" / "server.py")),  # absolute
                _finding("pkg/a.py"),  # already relative to the root
                _finding("/elsewhere/x.py"),  # outside: left alone
            ],
        )
    ]
    rebase_finding_paths(results, "src/app/server.py", str(tmp_path))
    assert [f.file for f in results[0].findings] == [
        "src/app/server.py",
        "src/app/server.py",
        "pkg/a.py",
        "/elsewhere/x.py",
    ]


def test_paths_file_scan_applies_argus_yml(tmp_path: Path, monkeypatch) -> None:
    """exclude_paths and suppressions match full paths in a PR scan too (they didn't: the
    findings said `server.py`, so `tests/**` and `**/app/server.py` never matched)."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("eval(user)\n")
    (tmp_path / "src" / "app").mkdir(parents=True)
    (tmp_path / "src" / "app" / "server.py").write_text("eval(user)\n")
    (tmp_path / "src" / "app" / "real.py").write_text("eval(user)\n")
    (tmp_path / ".argus.yml").write_text(
        'exclude_paths:\n  - "tests/**"\n'
        "suppressions:\n"
        "  - rule_id: injection-eval\n"
        '    path: "**/app/server.py"\n'
        '    reason: "reviewed"\n'
    )
    paths = tmp_path / "paths.txt"
    paths.write_text("tests/test_a.py\nsrc/app/server.py\nsrc/app/real.py\n")
    report = tmp_path / "report.json"
    main(
        [
            "scan", "code", ".", "--paths-file", str(paths), "--format", "json",
            "--output", str(report), "--fail-on", "never",
        ]
    )  # fmt: skip
    data = json.loads(report.read_text(encoding="utf-8"))
    files = {f["file"] for r in data["results"] for f in r["findings"]}
    assert files == {"src/app/real.py"}


def test_scan_of_a_missing_path_fails_instead_of_passing(tmp_path: Path, capsys) -> None:
    """A typo in the path used to print "100/100, looks good to launch" and exit 0."""
    missing = str(tmp_path / "no-such-folder")
    for scan_type in ("vibe", "sast", "secrets", "all"):
        assert main(["scan", scan_type, missing]) == 2
        assert "Target not found" in capsys.readouterr().err


def test_url_and_image_scans_are_not_path_checked(monkeypatch) -> None:
    from argus import cli

    assert "dast" not in cli._PATH_SCANS
    assert "container" not in cli._PATH_SCANS
