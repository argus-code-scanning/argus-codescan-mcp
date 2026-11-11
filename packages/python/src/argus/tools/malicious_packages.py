"""Known-malicious dependencies: lockfile packages checked against OSV ``MAL-`` records (#141).

OSV publishes the OpenSSF malicious-packages feed as ``MAL-YYYY-NNNN`` advisories. A malicious
package is worse than a vulnerable one, so every match is a critical finding.

Lockfiles are parsed locally (nothing is installed or executed). Only exact
``ecosystem / name / version`` triples are sent to ``api.osv.dev``. Set ``ARGUS_NO_NETWORK=1``
(or pass ``--no-network`` on the CLI) to skip the lookup entirely.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from argus.models import Finding, ScanResult, ScanType, Severity

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    try:
        import tomli as _toml  # type: ignore[no-redef]
    except ModuleNotFoundError:
        _toml = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

TOOL_NAME = "osv-malicious"
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
_BATCH_SIZE = 1000
_MAX_PACKAGES = 50_000
_MAX_DEPTH = 8
_TIMEOUT = 20
_SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        ".venv",
        "venv",
        ".tox",
        "__pycache__",
        "dist",
        "build",
        "vendor",
        ".next",
        "coverage",
        "target",
    }
)


def network_disabled() -> bool:
    return os.environ.get("ARGUS_NO_NETWORK", "").strip().lower() in {"1", "true", "yes"}


@dataclass(frozen=True)
class Package:
    ecosystem: str  # OSV ecosystem name: npm, PyPI, Packagist
    name: str
    version: str


# ── Lockfile parsers (pure functions: text in, packages out) ──────────────────


def _npm_package_lock(text: str) -> Iterator[Package]:
    data = json.loads(text)
    if not isinstance(data, dict):
        return
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2 and 3
        for key, entry in packages.items():
            if not key or not isinstance(entry, dict) or "node_modules/" not in key:
                continue
            if entry.get("link") or str(entry.get("resolved", "")).startswith("file:"):
                continue
            version = entry.get("version")
            name = entry.get("name") or key.rsplit("node_modules/", 1)[1]
            if isinstance(version, str) and isinstance(name, str):
                yield Package("npm", name, version)
        return

    def walk(deps: object) -> Iterator[Package]:  # lockfileVersion 1
        if not isinstance(deps, dict):
            return
        for name, entry in deps.items():
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if isinstance(version, str) and not version.startswith(("file:", "link:")):
                yield Package("npm", name, version)
            yield from walk(entry.get("dependencies"))

    yield from walk(data.get("dependencies"))


_YARN_HEADER = re.compile(r'^"?((?:@[^@/\s"]+/)?[^@\s"]+)@')
_YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')


def _yarn_lock(text: str) -> Iterator[Package]:
    """Yarn classic (v1) and Berry (v2+) lockfiles."""
    name: str | None = None
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if not line[0].isspace():
            name = None
            if line.startswith("__metadata"):
                continue
            first = line.split(",", 1)[0]
            if re.search(r"@(?:workspace|link|file|portal|patch):", first):
                continue
            match = _YARN_HEADER.match(first)
            name = match.group(1) if match else None
            continue
        if name:
            version = _YARN_VERSION.match(line)
            if version:
                yield Package("npm", name, version.group(1))
                name = None


def _pnpm_key(key: str) -> tuple[str, str] | None:
    key = key.lstrip("/").split("(", 1)[0]  # drop peer-dependency suffixes
    if "@" in key[1:]:  # v6+/v9: name@version
        name, _, version = key.rpartition("@")
    else:  # v5: name/version
        name, _, version = key.rpartition("/")
    if not name or not version or not version[0].isdigit():
        return None
    return name, version


def _pnpm_lock(text: str) -> Iterator[Package]:
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        return
    packages = data.get("packages")
    if not isinstance(packages, dict):
        return
    for key in packages:
        parsed = _pnpm_key(str(key))
        if parsed:
            yield Package("npm", *parsed)


def _toml_packages(text: str) -> Iterator[Package]:
    """poetry.lock and uv.lock: ``[[package]]`` tables with name and version."""
    if _toml is None:
        return
    data = _toml.loads(text)
    for entry in data.get("package", []):
        if not isinstance(entry, dict):
            continue
        source = entry.get("source")
        if isinstance(source, dict) and (
            "editable" in source or "virtual" in source or "path" in source
        ):
            continue
        name, version = entry.get("name"), entry.get("version")
        if isinstance(name, str) and isinstance(version, str):
            yield Package("PyPI", name, version)


_REQUIREMENT_PIN = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;#,\\]+)"
)


def _requirements(text: str) -> Iterator[Package]:
    for line in text.splitlines():
        match = _REQUIREMENT_PIN.match(line.strip())
        if match:
            yield Package("PyPI", match.group(1), match.group(2))


def _composer_lock(text: str) -> Iterator[Package]:
    data = json.loads(text)
    if not isinstance(data, dict):
        return
    for section in ("packages", "packages-dev"):
        entries = data.get(section)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name, version = entry.get("name"), entry.get("version")
            if isinstance(name, str) and isinstance(version, str):
                if re.match(r"^v\d", version):
                    version = version[1:]
                yield Package("Packagist", name, version)


_PARSERS: dict[str, Callable[[str], Iterator[Package]]] = {
    "package-lock.json": _npm_package_lock,
    "npm-shrinkwrap.json": _npm_package_lock,
    "yarn.lock": _yarn_lock,
    "pnpm-lock.yaml": _pnpm_lock,
    "poetry.lock": _toml_packages,
    "uv.lock": _toml_packages,
    "composer.lock": _composer_lock,
}


def _parser_for(name: str) -> Callable[[str], Iterator[Package]] | None:
    if name in _PARSERS:
        return _PARSERS[name]
    if name.startswith("requirements") and name.endswith(".txt"):
        return _requirements
    return None


def find_lockfiles(target: Path) -> list[Path]:
    if target.is_file():
        return [target] if _parser_for(target.name) else []
    found: list[Path] = []

    def walk(directory: Path, depth: int) -> None:
        if depth > _MAX_DEPTH:
            return
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            return
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in _SKIP_DIRS:
                    walk(entry, depth + 1)
            elif _parser_for(entry.name):
                found.append(entry)

    walk(target, 0)
    return found


def _normalise(package: Package) -> Package:
    if package.ecosystem == "PyPI":  # PEP 503
        return Package("PyPI", re.sub(r"[-_.]+", "-", package.name).lower(), package.version)
    return package


def collect_packages(
    target: Path,
) -> tuple[dict[Package, list[tuple[str, int]]], list[str], list[str]]:
    """Return {package: [(lockfile, line), ...]}, the lockfiles read, and parse errors."""
    root = target if target.is_dir() else target.parent
    packages: dict[Package, list[tuple[str, int]]] = {}
    lockfiles: list[str] = []
    errors: list[str] = []
    for lockfile in find_lockfiles(target):
        relative = lockfile.relative_to(root).as_posix()
        parser = _parser_for(lockfile.name)
        if parser is None:
            continue
        try:
            text = lockfile.read_text(encoding="utf-8", errors="replace")
            parsed = list(parser(text))
        except Exception as exc:  # malformed lockfile: note it, keep going
            errors.append(f"Could not parse {relative}: {exc}")
            continue
        lockfiles.append(relative)
        for package in parsed:
            key = _normalise(package)
            if key not in packages and len(packages) >= _MAX_PACKAGES:
                continue
            index = text.find(package.name)
            line = text.count("\n", 0, index) + 1 if index >= 0 else 1
            locations = packages.setdefault(key, [])
            if (relative, line) not in locations:
                locations.append((relative, line))
    return packages, lockfiles, errors


# ── OSV lookup ────────────────────────────────────────────────────────────────


def _post_querybatch(queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    body = json.dumps({"queries": queries}).encode("utf-8")
    request = urllib.request.Request(
        OSV_QUERYBATCH_URL,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "argus-scan"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:  # noqa: S310 (fixed https URL)
        data = json.loads(response.read().decode("utf-8"))
    results = data.get("results", []) if isinstance(data, dict) else []
    return [r if isinstance(r, dict) else {} for r in results]


def lookup_malicious(packages: list[Package]) -> dict[Package, list[str]]:
    """Map each package to the ``MAL-`` ids OSV lists for its exact version."""
    found: dict[Package, list[str]] = {}
    for start in range(0, len(packages), _BATCH_SIZE):
        batch = packages[start : start + _BATCH_SIZE]
        queries = [
            {"package": {"ecosystem": p.ecosystem, "name": p.name}, "version": p.version}
            for p in batch
        ]
        for package, result in zip(batch, _post_querybatch(queries)):
            ids = [
                str(v.get("id"))
                for v in result.get("vulns", []) or []
                if isinstance(v, dict) and str(v.get("id", "")).startswith("MAL-")
            ]
            if ids:
                found[package] = sorted(set(ids))
    return found


def _finding(package: Package, ids: list[str], lockfile: str, line: int) -> Finding:
    return Finding(
        title=f"Known malicious package: {package.name}@{package.version}",
        severity=Severity.CRITICAL,
        scan_type=ScanType.SCA,
        tool=TOOL_NAME,
        file=lockfile,
        line=line,
        rule_id=ids[0],
        confidence="high",
        description=(
            f"OSV lists {package.ecosystem} package {package.name}@{package.version} as "
            f"malicious ({', '.join(ids)}). This comes from the OpenSSF malicious-packages feed."
        ),
        fix_guidance=(
            "Remove the package and regenerate the lockfile. Treat every machine and CI runner "
            "that installed it as compromised: rotate credentials and tokens it could reach "
            "(npm, GitHub, cloud, SSH), and check install logs and recent publishes."
        ),
        references=[f"https://osv.dev/vulnerability/{vuln_id}" for vuln_id in ids],
    )


async def run_malicious_package_check(target: str) -> ScanResult:
    """Check lockfile packages against OSV known-malicious (MAL-) records."""
    result = ScanResult(tool=TOOL_NAME, scan_type=ScanType.SCA, target=target)
    target_path = Path(target)
    packages, lockfiles, errors = await asyncio.to_thread(collect_packages, target_path)
    result.errors.extend(errors)
    result.metadata["lockfiles"] = lockfiles
    result.metadata["packages_checked"] = len(packages)
    if not packages:
        return result
    if network_disabled():
        result.metadata["skipped"] = "network disabled (ARGUS_NO_NETWORK / --no-network)"
        return result
    try:
        malicious = await asyncio.to_thread(lookup_malicious, list(packages))
    except (OSError, ValueError, urllib.error.URLError) as exc:
        result.errors.append(f"OSV malicious-package check skipped: network unavailable ({exc})")
        return result
    for package, ids in sorted(malicious.items(), key=lambda item: item[0].name):
        for lockfile, line in packages[package]:
            result.findings.append(_finding(package, ids, lockfile, line))
    return result
