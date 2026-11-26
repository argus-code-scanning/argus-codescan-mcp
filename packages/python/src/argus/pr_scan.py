"""Choose PR scan targets from a git diff.

Pull-request CI scans each changed path. When more than ``limit`` files
change, callers fall back to a full scan of ``full_target``.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from argus.models import ScanResult

DEFAULT_PR_FILE_LIMIT = 50

ScanMode = Literal["changed", "full", "empty"]


@dataclass(frozen=True)
class ScanScope:
    """Paths a CI job should pass to the scanner."""

    mode: ScanMode
    paths: tuple[str, ...]
    changed_count: int
    limit: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "paths": list(self.paths),
            "changed_count": self.changed_count,
            "limit": self.limit,
        }


def read_paths_file(path: Path) -> list[str]:
    """Read scan targets from a file, one path per line.

    Blank lines and lines starting with ``#`` are ignored. Order is kept
    and duplicate paths are dropped.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Paths file not found: {path}")

    seen: set[str] = set()
    paths: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line in seen:
            continue
        seen.add(line)
        paths.append(line)
    return paths


def select_scan_scope(
    changed_files: list[str],
    *,
    limit: int = DEFAULT_PR_FILE_LIMIT,
    full_target: str = ".",
    repo_root: Path | None = None,
) -> ScanScope:
    """Pick changed-file targets, a full scan, or an empty scan.

    ``changed_count`` is the number of names from the diff, including paths
    that no longer exist. Only paths that exist under ``repo_root`` are
    returned for a changed-file scan. A diff that only deletes files yields
    ``mode="empty"`` so CI does not rescan the repository.
    """
    if limit < 1:
        raise ValueError("limit must be >= 1")

    names: list[str] = []
    seen: set[str] = set()
    for raw in changed_files:
        name = raw.strip()
        if not name or name in seen:
            continue
        seen.add(name)
        names.append(name)

    if len(names) > limit:
        return ScanScope(
            mode="full",
            paths=(full_target,),
            changed_count=len(names),
            limit=limit,
        )

    root = repo_root if repo_root is not None else Path()
    present = tuple(name for name in names if (root / name).exists())
    if not present:
        return ScanScope(mode="empty", paths=(), changed_count=len(names), limit=limit)
    return ScanScope(mode="changed", paths=present, changed_count=len(names), limit=limit)


def git_changed_files(repo: Path, base: str, head: str = "HEAD") -> list[str]:
    """Return added, copied, modified, and renamed paths between two git revisions.

    Deletions are omitted (``--diff-filter=ACMR``). Paths are relative to ``repo``.
    """
    cmd = [
        "git",
        "-C",
        str(repo),
        "diff",
        "-z",
        "--name-only",
        "--diff-filter=ACMR",
        base,
        head,
    ]
    completed = subprocess.run(cmd, check=True, capture_output=True)
    return [part.decode() for part in completed.stdout.split(b"\0") if part]


def resolve_pr_scan_scope(
    repo: Path,
    base: str,
    head: str = "HEAD",
    *,
    limit: int = DEFAULT_PR_FILE_LIMIT,
    full_target: str = ".",
) -> ScanScope:
    """Diff ``base``..``head`` and choose the PR scan scope."""
    changed = git_changed_files(repo, base, head)
    return select_scan_scope(changed, limit=limit, full_target=full_target, repo_root=repo)


def write_github_output(path: Path, scope: ScanScope) -> None:
    """Append ``mode`` and ``changed_count`` for a GitHub Actions step output."""
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"mode={scope.mode}\n")
        handle.write(f"changed_count={scope.changed_count}\n")


def format_scope(scope: ScanScope) -> str:
    """JSON rendering used by ``argus ci pr-paths``."""
    return json.dumps(scope.to_dict(), indent=2) + "\n"


def rebase_finding_paths(results: list[ScanResult], scanned: str, root: str) -> None:
    """Make finding paths relative to the repository root after scanning one path.

    With ``--paths-file`` each changed file is scanned as its own target, so scanners report
    ``server.py`` instead of ``packages/python/src/argus/server.py``. ``.argus.yml``
    exclude_paths and suppressions (``tests/**``, ``**/argus/server.py``) and the PR comment
    need the full path, the same one a whole-repository scan reports.
    """
    root_path = Path(root).resolve()
    scanned_path = Path(scanned)
    if not scanned_path.is_absolute():
        scanned_path = (Path.cwd() / scanned_path).resolve()
    base = scanned_path if scanned_path.is_dir() else scanned_path.parent
    for result in results:
        for finding in result.findings:
            if not finding.file:
                continue
            reported = Path(finding.file)
            if reported.is_absolute():
                candidate = reported
            elif len(reported.parts) > 1 and (root_path / reported).exists():
                continue  # already relative to the repository root
            elif not scanned_path.is_dir() and reported.name == scanned_path.name:
                candidate = scanned_path
            else:
                candidate = base / reported
            try:
                finding.file = candidate.resolve().relative_to(root_path).as_posix()
            except ValueError:
                continue  # outside the repository: leave it as reported


def merge_results_by_tool(results: list[ScanResult]) -> list[ScanResult]:
    """Collapse per-path results so each tool appears once.

    Findings are concatenated. Identical error strings are kept once, which
    avoids repeating "tool is not installed" for every changed file.
    """
    merged: dict[str, ScanResult] = {}
    order: list[str] = []
    for result in results:
        current = merged.get(result.tool)
        if current is None:
            merged[result.tool] = result
            order.append(result.tool)
            continue
        current.findings.extend(result.findings)
        for error in result.errors:
            if error not in current.errors:
                current.errors.append(error)
        if not result.tool_available:
            current.tool_available = False
    return [merged[name] for name in order]
