"""Known vulnerabilities in dependencies from every lockfile, via OSV (no extra tools).

Covers npm (yarn, pnpm, package-lock), PyPI (poetry, uv, Pipfile, requirements), Go (go.mod,
including the Go toolchain), Dart / Flutter (pubspec.lock), Rust (Cargo.lock), Ruby
(Gemfile.lock), .NET (packages.lock.json) and PHP (composer.lock). Maven and Gradle have their
own check (``maven_deps``).

An ecosystem is left to its own tool when that tool is installed, so advisories are not
reported twice: Trivy covers all of them; npm audit covers package-lock.json, pip-audit PyPI,
govulncheck Go and composer audit PHP.

Each finding says which version is installed, how it gets into the project ("via a › b"),
whether it is dev-only (lowered one level, like findings in tests) and how to fix it in that
ecosystem. Only ``ecosystem / name / version`` triples are sent to api.osv.dev; set
``ARGUS_NO_NETWORK=1`` (``--no-network``) to skip the check.
"""

from __future__ import annotations

import asyncio
import urllib.error
from pathlib import Path
from typing import Any

from argus.models import Finding, ScanResult, ScanType, Severity
from argus.tools import malicious_packages as mp
from argus.tools.dep_graph import ARROW, DependencyGraph, read_graph
from argus.tools.malicious_packages import Package
from argus.tools.maven_deps import (
    _MAX_DETAIL_LOOKUPS,
    _SEVERITY,
    _fetch_all,
    _fixed_versions,
    _upgrade_targets,
    _version_key,
)
from argus.utils import is_tool_available

TOOL_NAME = "osv-deps"

_NPM_LOCKS = {"package-lock.json", "npm-shrinkwrap.json"}
_DOWNGRADE = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFO,
}
_LABELS = {
    "npm": "npm",
    "PyPI": "Python",
    "Go": "Go",
    "Pub": "Dart / Flutter",
    "crates.io": "Rust",
    "RubyGems": "Ruby",
    "NuGet": ".NET",
    "Packagist": "PHP",
}


def covered_elsewhere(package: Package, lockfiles: list[str]) -> str:
    """Name of the installed tool that already audits this package, or ''."""
    names = [Path(lock).name for lock in lockfiles]
    if package.ecosystem == "npm" and is_tool_available("npm"):
        if all(name in _NPM_LOCKS for name in names):
            return "npm audit"
    if package.ecosystem == "PyPI" and is_tool_available("pip-audit"):
        # pip-audit reads requirements files, not poetry.lock / uv.lock / Pipfile.lock.
        if all(name.startswith("requirements") and name.endswith(".txt") for name in names):
            return "pip-audit"
    if package.ecosystem == "Go" and is_tool_available("govulncheck") and is_tool_available("go"):
        return "govulncheck"
    if package.ecosystem == "Packagist" and is_tool_available("composer"):
        return "composer audit"
    return ""


def _go_toolchain(package: Package) -> bool:
    return package.ecosystem == "Go" and package.name == "stdlib"


def fix_advice(package: Package, target: str, paths: list[str], unfixed: int = 0) -> str:
    """How to move to ``target`` (the version that fixes every advisory) in this ecosystem."""
    name = package.name
    still = (
        f" {unfixed} {'advisory has' if unfixed == 1 else 'advisories have'} no fix yet."
        if unfixed
        else ""
    )
    if not target:
        return (
            f"No patched version of {name} is published yet. Check the advisories for "
            "workarounds and update when a fix is released."
        )
    if _go_toolchain(package):
        return f"Build with Go {target} or later (set `toolchain go{target}` in go.mod).{still}"
    transitive = bool(paths) and all(ARROW in p for p in paths)
    if transitive:
        pin = {
            "npm": f'add "overrides": {{"{name}": "{target}"}} to package.json',
            "PyPI": f"add {name}>={target} to your requirements or constraints",
            "Go": f"run go get {name}@v{target.lstrip('v')} and go mod tidy",
            "Pub": f"add {name}: ^{target} under dependency_overrides in pubspec.yaml",
            "crates.io": f"run cargo update -p {name} --precise {target}",
            "RubyGems": f"run bundle update {name}",
            "NuGet": f'add <PackageReference Include="{name}" Version="{target}" />',
            "Packagist": f"run composer update {name} --with-dependencies",
        }.get(package.ecosystem, f"upgrade {name}")
        via = paths[0].split(ARROW)[0]
        return f"Upgrade {name} to {target}: update {via}, which brings it in, or {pin}.{still}"
    how = {
        "npm": f"npm install {name}@{target}",
        "PyPI": f"set {name}>={target} in your requirements, pyproject or Pipfile and re-lock",
        "Go": f"go get {name}@v{target.lstrip('v')} and go mod tidy",
        "Pub": f"set {name}: ^{target} in pubspec.yaml, then flutter pub upgrade {name}",
        "crates.io": f'set {name} = "{target}" in Cargo.toml, then cargo update -p {name}',
        "RubyGems": f"bundle update {name}",
        "NuGet": f"update the PackageReference for {name} to {target}",
        "Packagist": f"composer require {name}:^{target}",
    }.get(package.ecosystem, f"upgrade {name}")
    return f"Upgrade {name} to {target} ({how}).{still}"


def _severity(details: dict[str, Any], related: dict[str, dict[str, Any]]) -> Severity:
    """GHSA label on the record, else on a GHSA alias we already fetched; HIGH when unknown."""
    for record in (details, *(related.get(a, {}) for a in details.get("aliases", []) or [])):
        label = str((record.get("database_specific") or {}).get("severity", "")).lower()
        if label in _SEVERITY:
            return _SEVERITY[label]
    return Severity.HIGH


def _finding(
    package: Package,
    advisories: list[tuple[str, dict[str, Any]]],
    related: dict[str, dict[str, Any]],
    lockfile: str,
    line: int,
    graph: DependencyGraph,
) -> Finding:
    """One finding per package and lockfile, covering every advisory for its version."""
    rank = {s: i for i, s in enumerate(Severity)}
    scored = sorted(
        ((_severity(details, related), vuln_id, details) for vuln_id, details in advisories),
        key=lambda item: (rank[item[0]], item[1]),
    )
    severity, top_id, top = scored[0]
    cves = sorted(
        {a for _, _, d in scored for a in d.get("aliases", []) or [] if str(a).startswith("CVE-")}
    )
    # The version that fixes every advisory: the highest of each one's nearest fix.
    targets, unfixed = [], 0
    for _, _, details in scored:
        nearest = [
            v
            for v in _upgrade_targets(package.version, _fixed_versions(details, package.name))
            if _version_key(v) > _version_key(package.version)
        ]
        if nearest:
            targets.append(nearest[0])
        else:
            unfixed += 1
    target = max(targets, key=_version_key) if targets else ""
    paths = [] if _go_toolchain(package) else graph.paths_to(package.name)
    dev = graph.is_dev_only(package.name)
    if dev:
        severity = _DOWNGRADE.get(severity, severity)
    if _go_toolchain(package):
        subject, how = f"Go toolchain {package.version}", "toolchain in go.mod"
    else:
        label = _LABELS.get(package.ecosystem, package.ecosystem)
        subject = f"{label} package {package.name} {package.version}"
        if package.name in graph.direct:
            how = "direct dependency"
        elif paths:
            how = "via " + paths[0].rsplit(ARROW, 1)[0]
        else:
            how = "transitive dependency"
    summary = str(top.get("summary") or "").strip() or f"Known vulnerability {top_id}"
    count = len(scored)
    name = "Go toolchain" if _go_toolchain(package) else package.name
    title = f"{name}: {summary}" if count == 1 else f"{name}: {count} known vulnerabilities"
    ids = [vuln_id for _, vuln_id, _ in scored]
    shown = ", ".join(ids[:5]) + (f" and {count - 5} more" if count > 5 else "")
    return Finding(
        title=title,
        severity=severity,
        scan_type=ScanType.SCA,
        tool=TOOL_NAME,
        file=lockfile,
        line=line,
        rule_id=top_id,
        cve=", ".join(cves[:10]),
        confidence="high",
        context="dev-dependency" if dev else "",
        description=(
            f"[{'dev' if dev else 'runtime'} dependency] {subject} ({how}): {shown}"
            + ("" if count == 1 else f". Most severe: {summary}")
        ),
        fix_guidance=fix_advice(package, target, paths, unfixed),
        references=[f"https://osv.dev/vulnerability/{vuln_id}" for vuln_id in ids[:5]],
        package=package.name,
        version=package.version,
        dependency_paths=paths,
    )


async def run_osv_dependency_check(target: str) -> ScanResult:
    """Known vulnerabilities in every non-Maven lockfile under ``target``, from OSV."""
    result = ScanResult(tool=TOOL_NAME, scan_type=ScanType.SCA, target=target)
    root = Path(target) if Path(target).is_dir() else Path(target).parent
    collected, _lockfiles, errors = await asyncio.to_thread(mp.collect_packages, Path(target))
    result.errors.extend(errors)
    packages = {p: locs for p, locs in collected.items() if p.ecosystem != "Maven"}
    result.metadata["packages_checked"] = len(packages)
    if not packages:
        return result
    if is_tool_available("trivy"):
        result.metadata["skipped"] = "Trivy is installed and covers these lockfiles"
        return result
    covered: dict[str, int] = {}
    todo: dict[Package, list[tuple[str, int]]] = {}
    for package, locations in packages.items():
        tool = covered_elsewhere(package, [loc for loc, _ in locations])
        if tool:
            covered[tool] = covered.get(tool, 0) + 1
        else:
            todo[package] = locations
    if covered:
        result.metadata["covered_by"] = covered
    if not todo:
        return result
    if mp.network_disabled():
        result.metadata["skipped"] = "network disabled (ARGUS_NO_NETWORK / --no-network)"
        return result
    try:
        ids_by_package = await asyncio.to_thread(mp.query_vulnerability_ids, list(todo))
        # MAL- records are reported by the known-malicious check.
        ids_by_package = {
            p: [i for i in ids if not i.startswith("MAL-")] for p, ids in ids_by_package.items()
        }
        unique_ids = sorted({i for ids in ids_by_package.values() for i in ids})
        lookups = unique_ids[:_MAX_DETAIL_LOOKUPS]
        details = await asyncio.to_thread(_fetch_all, lookups)
        # Go advisories (GO-...) carry no severity; their GHSA alias does.
        missing = sorted(
            {
                alias
                for record in details.values()
                if not (record.get("database_specific") or {}).get("severity")
                for alias in record.get("aliases", []) or []
                if str(alias).startswith("GHSA-") and alias not in details
            }
        )[: max(0, _MAX_DETAIL_LOOKUPS - len(lookups))]
        related = {**details, **(await asyncio.to_thread(_fetch_all, missing) if missing else {})}
    except (OSError, ValueError, urllib.error.URLError) as exc:
        result.errors.append(f"OSV dependency check skipped: network unavailable ({exc})")
        return result
    if len(unique_ids) > len(lookups):
        result.errors.append(
            f"{len(unique_ids) - len(lookups)} more advisories were not looked up "
            f"(limit {_MAX_DETAIL_LOOKUPS})"
        )
    graphs: dict[str, DependencyGraph] = {}
    for package in sorted(ids_by_package, key=lambda p: (p.ecosystem, p.name)):
        advisories = [(i, details[i]) for i in ids_by_package[package] if i in details]
        if not advisories:
            continue
        for lockfile, line in todo[package]:
            if lockfile not in graphs:
                graphs[lockfile] = await asyncio.to_thread(read_graph, root / lockfile)
            result.findings.append(
                _finding(package, advisories, related, lockfile, line, graphs[lockfile])
            )
    severity_rank = {s: i for i, s in enumerate(Severity)}
    result.findings.sort(key=lambda f: severity_rank.get(f.severity, 99))
    return result
