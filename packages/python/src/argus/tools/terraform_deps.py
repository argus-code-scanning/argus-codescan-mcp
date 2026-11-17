"""Terraform dependencies: how modules and providers are pinned.

OSV has no Terraform database, so the dependency risk in Terraform is what gets downloaded at
``terraform init``. Same checks and ids as the npm scanner (terraform-deps.ts):

- tf-module-insecure-source (high): module downloaded over plain http:// or git:// (unencrypted)
- tf-module-git-unpinned (moderate): git module without ?ref=, or on a branch (main, master, ...)
- tf-module-registry-unpinned (moderate): registry module without a version
- tf-provider-unpinned (low): required_providers entry without a version constraint
- tf-lockfile-missing (low): root module with providers but no .terraform.lock.hcl

Pinning a git module to a commit SHA, or a registry module to an exact version, means a
compromised upstream can't change what your next plan runs.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from argus_languages.noise import path_context

from argus.models import Finding, ScanResult, ScanType, Severity
from argus.utils import find_scan_files

TOOL_NAME = "terraform-deps"
_BRANCHES = {"main", "master", "develop", "dev", "trunk", "head", "latest", "staging", "prod"}
_SHA = re.compile(r"^[0-9a-f]{40}$")
_BLOCK = re.compile(r'^\s*(module|terraform)\b\s*(?:"([^"]+)")?\s*\{', re.MULTILINE)
_ATTR = re.compile(r'^\s*(source|version)\s*=\s*"([^"]*)"', re.MULTILINE)


@dataclass
class _Issue:
    rule: str
    severity: Severity
    title: str
    line: int
    fix: str


def _block_end(text: str, start: int) -> int:
    """Index just past the brace that closes the block opening at ``start`` (a '{')."""
    depth, i, quote = 0, start, False
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == '"':
                quote = False
        elif ch == '"':
            quote = True
        elif ch == "#" or text.startswith("//", i):
            nl = text.find("\n", i)
            i = len(text) if nl < 0 else nl
            continue
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(text)


def _top_level_attrs(body: str) -> dict[str, str]:
    """``source`` / ``version`` of a block, ignoring nested blocks."""
    attrs: dict[str, str] = {}
    depth = 0
    for line in body.splitlines():
        if depth == 0:
            match = _ATTR.match(line)
            if match:
                attrs.setdefault(match.group(1), match.group(2))
        depth += line.count("{") - line.count("}")
    return attrs


def _line(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _module_issue(name: str, source: str, version: str | None, line: int) -> _Issue | None:
    lowered = source.lower()
    if source.startswith(("./", "../")) or not source:
        return None
    if lowered.startswith(("http://", "git::http://", "git://", "git::git://")):
        return _Issue(
            "tf-module-insecure-source",
            Severity.HIGH,
            f'Module "{name}" is downloaded without encryption ({source.split("?")[0]})',
            line,
            "Use an https:// or ssh source so the module can't be swapped in transit.",
        )
    is_git = lowered.startswith(("git::", "git@", "github.com/", "bitbucket.org/")) or (
        ".git" in lowered and "://" in lowered
    )
    if is_git:
        ref = re.search(r"[?&]ref=([^&]+)", source)
        if not ref:
            problem = "has no ?ref=, so it follows the default branch"
        elif ref.group(1).lower() in _BRANCHES:
            problem = f"uses the branch {ref.group(1)!r}, which can change"
        else:
            return None
        return _Issue(
            "tf-module-git-unpinned",
            Severity.MEDIUM,
            f'Git module "{name}" {problem}',
            line,
            "Pin it to a commit SHA (?ref=<40-character SHA>) or at least a release tag.",
        )
    registry = re.fullmatch(r"(?:[\w.-]+/)?[\w-]+/[\w-]+/[\w-]+(?://.*)?", source)
    if registry and "://" not in source and not version:
        return _Issue(
            "tf-module-registry-unpinned",
            Severity.MEDIUM,
            f'Registry module "{name}" ({source}) has no version, so init takes the latest',
            line,
            'Add version = "x.y.z" (an exact version) to the module block.',
        )
    return None


def _provider_issues(block: str, offset_line: int) -> Iterator[_Issue]:
    match = re.search(r"\brequired_providers\s*\{", block)
    if not match:
        return
    start = match.end() - 1
    body = block[start + 1 : _block_end(block, start) - 1]
    for entry in re.finditer(r"^\s*([\w-]+)\s*=\s*(\{|\")", body, re.MULTILINE):
        if entry.group(2) == '"':
            continue  # legacy  aws = "~> 4.0"
        brace = entry.end() - 1
        spec = body[brace : _block_end(body, brace)]
        if re.search(r"(?:^|[\s,{])version\s*=", spec):
            continue
        source = re.search(r'source\s*=\s*"([^"]+)"', spec)
        name = source.group(1) if source else entry.group(1)
        yield _Issue(
            "tf-provider-unpinned",
            Severity.LOW,
            f"Provider {name} has no version constraint",
            offset_line + block.count("\n", 0, start + 1 + entry.start(1)),
            'Add version = "~> x.y" so a new major release is not picked up by surprise.',
        )


_ROOT_MARKER = re.compile(
    r'^\s*(?:backend\s+"[\w-]+"|cloud|provider\s+"[\w-]+")\s*\{', re.MULTILINE
)


def check_file(text: str) -> tuple[list[_Issue], bool]:
    """Issues in one .tf file, and whether it looks like a root module (backend, cloud or a
    provider configuration), which is where ``terraform init`` writes the lockfile."""
    issues: list[_Issue] = []
    root_module = bool(_ROOT_MARKER.search(text))
    for match in _BLOCK.finditer(text):
        open_brace = match.end() - 1
        end = _block_end(text, open_brace)
        block = text[match.start(1) : end]
        line = _line(text, match.start(1))
        if match.group(1) == "module":
            attrs = _top_level_attrs(text[open_brace + 1 : end - 1])
            issue = _module_issue(
                match.group(2) or "", attrs.get("source", ""), attrs.get("version"), line
            )
            if issue:
                issues.append(issue)
        else:
            issues.extend(_provider_issues(block, line))
    return issues, root_module


_DOWNGRADE = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFO,
}


def _finding(issue: _Issue, path: str) -> Finding:
    # examples/, docs/ and test fixtures are lowered one level, like the rule packs do.
    context = path_context(path)
    return Finding(
        title=issue.title,
        severity=_DOWNGRADE.get(issue.severity, issue.severity) if context else issue.severity,
        context=context,
        scan_type=ScanType.SCA,
        tool=TOOL_NAME,
        file=path,
        line=issue.line,
        rule_id=issue.rule,
        confidence="high",
        fix_guidance=issue.fix,
    )


async def run_terraform_dependency_check(target: str) -> ScanResult:
    result = ScanResult(tool=TOOL_NAME, scan_type=ScanType.SCA, target=target)
    target_path = Path(target)
    root = target_path if target_path.is_dir() else target_path.parent
    files = [target_path] if target_path.suffix == ".tf" else find_scan_files(target_path, "*.tf")
    files = [f for f in files if ".terraform" not in f.parts]
    result.metadata["files_checked"] = len(files)
    provider_dirs: set[Path] = set()
    for path in sorted(files):
        try:
            text = await asyncio.to_thread(path.read_text, encoding="utf-8", errors="replace")
        except OSError:
            continue
        issues, root_module = check_file(text)
        if root_module:
            provider_dirs.add(path.parent)
        rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path)
        result.findings.extend(_finding(issue, rel) for issue in issues)
    for directory in sorted(provider_dirs):
        if not (directory / ".terraform.lock.hcl").exists():
            rel = (
                directory.relative_to(root).as_posix()
                if directory.is_relative_to(root)
                else str(directory)
            )
            where = "." if rel in ("", ".") else rel
            result.findings.append(
                _finding(
                    _Issue(
                        "tf-lockfile-missing",
                        Severity.LOW,
                        f"No .terraform.lock.hcl in {where}: provider versions and checksums "
                        "are not locked",
                        0,
                        "Run terraform init and commit .terraform.lock.hcl, so every run uses the "
                        "same provider builds (checked against their hashes).",
                    ),
                    f"{where}/.terraform.lock.hcl" if where != "." else ".terraform.lock.hcl",
                )
            )
    return result
