"""Typosquatted and non-existent dependencies (#142).

1. **Lookalike names (offline, always on):** each *direct* dependency in package.json,
   requirements*.txt and pyproject.toml is compared with the bundled top-5,000 npm / PyPI
   names (``argus/data/top_*.txt``, refreshed by ``scripts/refresh_top_packages.py``). One or
   two character edits, separator swaps (``lodash-merge`` / ``lodash.merge``), ``py``/``js``/
   ``node-``/``python-`` affixes and homoglyphs (``0``→``o``, ``rn``→``m``) are reported.
   A dependency that is itself popular is never reported.
2. **Existence and age (online, opt-in ``--registry-check`` / ``ARGUS_REGISTRY_CHECK=1``):**
   dependencies that don't exist on the public registry (often names an AI assistant made up,
   which anyone can register: "slopsquatting") and packages first published in the last 30 days.
   Skipped for projects that use a private registry, and with ``--no-network``.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from importlib import resources
from pathlib import Path

from argus_languages.noise import path_context

from argus.models import Finding, ScanResult, ScanType, Severity

TOOL_NAME = "argus-typosquats"
_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        ".next",
        "target",
        ".tox",
        "vendor",
    }
)
_NEW_PACKAGE_DAYS = 30
_MAX_REGISTRY_LOOKUPS = 300
# Attackers copy the most-downloaded packages: edit-distance matching only targets the top
# names, while every name in the bundled lists (top ~15k) counts as an established package.
_DISTANCE_TARGETS = {"pypi": 1500, "npm": 5000}
_AFFIX_TARGETS = 5000
# Frequent typosquat targets that rank low on dependency-based popularity lists (apps install
# them; few libraries depend on them).
_EXTRA_TARGETS = {
    "npm": frozenset(
        {
            "electron",
            "discord.js",
            "ethers",
            "web3",
            "puppeteer",
            "playwright",
            "jsonwebtoken",
            "bcrypt",
            "dotenv",
            "nodemailer",
            "mongoose",
            "mongodb",
            "socket.io",
            "react-native",
            "next",
            "nuxt",
            "vue",
            "svelte",
            "typescript",
            "webpack",
            "vite",
            "@solana/web3.js",
        }
    ),
    "pypi": frozenset(
        {"requests", "colorama", "discord.py", "web3", "openai", "anthropic", "selenium"}
    ),
}
_AFFIXES = ("python-", "-python", "py-", "-py", "py", "node-", "-node", "js-", "-js", ".js", "js")
_HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"))


@dataclass(frozen=True)
class Dependency:
    ecosystem: str  # "npm" | "pypi"
    name: str  # as written
    manifest: str
    line: int


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@lru_cache(maxsize=2)
def popular(ecosystem: str) -> dict[str, int]:
    """name -> rank (0 = most popular)."""
    text = (
        resources.files("argus")
        .joinpath("data")
        .joinpath(f"top_{ecosystem}.txt")
        .read_text("utf-8")
    )
    names = [n.strip() for n in text.splitlines() if n.strip() and not n.startswith("#")]
    normalise = _pep503 if ecosystem == "pypi" else str.lower
    ranks: dict[str, int] = {}
    for rank, name in enumerate(names):
        ranks.setdefault(normalise(name), rank)
    return ranks


# ── Manifests ─────────────────────────────────────────────────────────────────

_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_PEP508_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _line_of(text: str, needle: str) -> int:
    index = text.find(needle)
    return text.count("\n", 0, index) + 1 if index >= 0 else 1


def parse_manifest(path: Path, relative: str) -> list[Dependency]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    deps: list[Dependency] = []
    name = path.name
    if name == "package.json":
        try:
            data = json.loads(text)
        except ValueError:
            return []
        if not isinstance(data, dict):
            return []
        for section in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            table = data.get(section)
            if isinstance(table, dict):
                for dep in table:
                    deps.append(Dependency("npm", dep, relative, _line_of(text, f'"{dep}"')))
    elif name.startswith("requirements") and name.endswith(".txt"):
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(
                ("#", "-", "git+", "http://", "https://", ".", "/")
            ):
                continue
            match = _REQ_NAME.match(stripped)
            if match:
                deps.append(Dependency("pypi", match.group(1), relative, number))
    elif name == "pyproject.toml":
        from argus.tools.malicious_packages import _toml

        if _toml is None:
            return []
        try:
            data = _toml.loads(text)
        except ValueError:
            return []
        specs: list[str] = []
        project = data.get("project", {})
        if isinstance(project, dict):
            specs += [s for s in project.get("dependencies", []) if isinstance(s, str)]
            for group in (project.get("optional-dependencies") or {}).values():
                specs += [s for s in group if isinstance(s, str)]
        for group in (data.get("dependency-groups") or {}).values():
            specs += [s for s in group if isinstance(s, str)]
        poetry = (data.get("tool") or {}).get("poetry") or {}
        for table in (poetry.get("dependencies"), poetry.get("dev-dependencies")):
            if isinstance(table, dict):
                specs += [k for k in table if k.lower() != "python"]
        for group in (poetry.get("group") or {}).values():
            if isinstance(group, dict) and isinstance(group.get("dependencies"), dict):
                specs += list(group["dependencies"])
        for spec in specs:
            match = _PEP508_NAME.match(spec)
            if match:
                dep = match.group(1)
                deps.append(Dependency("pypi", dep, relative, _line_of(text, dep)))
    return deps


def collect_dependencies(root: Path) -> list[Dependency]:
    base = root if root.is_dir() else root.parent
    manifests: list[Path] = []
    if root.is_file():
        manifests = [root]
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for name in filenames:
                if name in ("package.json", "pyproject.toml") or (
                    name.startswith("requirements") and name.endswith(".txt")
                ):
                    manifests.append(Path(dirpath) / name)
    deps: list[Dependency] = []
    for path in manifests:
        relative = path.relative_to(base).as_posix()
        if path_context(relative):  # fixtures and examples aren't your dependencies
            continue
        deps.extend(parse_manifest(path, relative))
    return deps


# ── Lookalike names ───────────────────────────────────────────────────────────


def _distance(a: str, b: str, limit: int) -> int:
    """Damerau-Levenshtein (optimal string alignment) distance, capped at limit + 1."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    previous2: list[int] = []
    previous = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        current = [i] + [0] * len(b)
        best = current[0]
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                current[j] = min(current[j], previous2[j - 2] + 1)
            best = min(best, current[j])
        if best > limit:
            return limit + 1
        previous2, previous = previous, current
    return previous[-1]


def _strip_separators(name: str) -> str:
    return re.sub(r"[-_.]", "", name)


def _deglyph(name: str) -> str:
    for fake, real in _HOMOGLYPHS:
        name = name.replace(fake, real)
    return name


@lru_cache(maxsize=2)
def _index(ecosystem: str) -> tuple[dict[int, list[str]], dict[str, str], dict[str, str]]:
    names = popular(ecosystem)
    by_length: dict[int, list[str]] = {}
    no_separators: dict[str, str] = {}
    deglyphed: dict[str, str] = {}
    for name in sorted(names, key=names.__getitem__):
        rank = names[name]
        if rank >= _AFFIX_TARGETS and name not in _EXTRA_TARGETS[ecosystem]:
            continue
        bare = name.split("/", 1)[-1]
        if rank < _DISTANCE_TARGETS[ecosystem] or name in _EXTRA_TARGETS[ecosystem]:
            by_length.setdefault(len(name), []).append(name)
        no_separators.setdefault(_strip_separators(name), name)
        deglyphed.setdefault(_deglyph(bare), name)
    return by_length, no_separators, deglyphed


def lookalike(ecosystem: str, dep_name: str) -> tuple[str, str] | None:
    """(popular name, how it differs) when dep_name imitates a popular package."""
    names = popular(ecosystem)
    name = _pep503(dep_name) if ecosystem == "pypi" else dep_name.lower()
    if name in names:
        return None
    if name.startswith("@"):  # scoped npm: a scope can only be published to by its owner
        scope = name.split("/", 1)[0]
        if any(p.startswith(scope + "/") for p in names):
            return None
    by_length, no_separators, deglyphed = _index(ecosystem)
    stripped = _strip_separators(name)
    if len(stripped) >= 4 and stripped in no_separators and no_separators[stripped] != name:
        return no_separators[stripped], "differs only in - _ . separators"
    for affix in _AFFIXES:
        for base in (
            name[len(affix) :] if name.startswith(affix) else None,
            name[: -len(affix)] if name.endswith(affix) else None,
        ):
            if base and len(base) >= 4 and names.get(base, _AFFIX_TARGETS) < _AFFIX_TARGETS:
                return base, f"adds '{affix}' to the name"
    bare = name.split("/", 1)[-1]
    glyph = _deglyph(bare)
    if glyph != bare and glyph in deglyphed and deglyphed[glyph] != name:
        return deglyphed[glyph], "uses look-alike characters"
    best: tuple[int, str] | None = None
    for length in range(len(name) - 1, len(name) + 2):
        for candidate in by_length.get(length, ()):
            if min(len(candidate), len(name)) < 5:
                continue  # short names are one edit from many others
            if re.sub(r"\d", "", candidate) == re.sub(r"\d", "", name):
                continue  # version-style differences: cu11 / cu12, bump2version
            if _distance(name, candidate, 1) <= 1:
                rank = names[candidate]
                if best is None or rank < best[0]:
                    best = (rank, candidate)
    if best:
        return best[1], "is one character away"
    return None


# ── Registry existence and age (opt-in) ───────────────────────────────────────


def network_disabled() -> bool:
    return os.environ.get("ARGUS_NO_NETWORK", "").strip().lower() in {"1", "true", "yes"}


def registry_check_enabled() -> bool:
    return os.environ.get("ARGUS_REGISTRY_CHECK", "").strip().lower() in {"1", "true", "yes"}


def uses_private_registry(root: Path, ecosystem: str) -> bool:
    """A private registry or index means "not on the public registry" proves nothing."""
    base = root if root.is_dir() else root.parent
    if ecosystem == "npm":
        npmrc = base / ".npmrc"
        if npmrc.is_file():
            text = npmrc.read_text(encoding="utf-8", errors="replace")
            return bool(re.search(r"registry\s*=\s*https?://(?!registry\.npmjs\.org)", text))
        return False
    for path in [*base.glob("requirements*.txt"), base / "pip.conf", base / "pyproject.toml"]:
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            if re.search(
                r"--(?:extra-)?index-url|\[\[tool\.(?:poetry\.source|uv\.index)\]\]|index-url\s*=",
                text,
            ):
                return True
    return False


def _fetch_json(url: str) -> dict | None:
    request = urllib.request.Request(
        url, headers={"User-Agent": "argus-scan", "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310 (fixed https hosts)
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def registry_status(ecosystem: str, name: str) -> tuple[bool, datetime | None]:
    """(exists, first published) for one package on the public registry."""
    if ecosystem == "npm":
        data = _fetch_json(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}")
        if data is None:
            return False, None
        created = (data.get("time") or {}).get("created")
    else:
        data = _fetch_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
        if data is None:
            return False, None
        uploads = [
            f.get("upload_time_iso_8601")
            for files in (data.get("releases") or {}).values()
            for f in files
            if f.get("upload_time_iso_8601")
        ]
        created = min(uploads) if uploads else None
    when = (
        datetime.fromisoformat(created.replace("Z", "+00:00")) if isinstance(created, str) else None
    )
    return True, when


# ── Findings ──────────────────────────────────────────────────────────────────


def _finding(
    dep: Dependency,
    rule_id: str,
    title: str,
    severity: Severity,
    confidence: str,
    detail: str,
    fix: str,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        scan_type=ScanType.SCA,
        tool=TOOL_NAME,
        file=dep.manifest,
        line=dep.line,
        rule_id=rule_id,
        confidence=confidence,
        description=detail,
        fix_guidance=fix,
        cwe="CWE-1357",
    )


def typosquat_findings(target: str) -> tuple[list[Finding], dict[str, object]]:
    root = Path(target)
    deps = collect_dependencies(root)
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for dep in deps:
        key = (dep.ecosystem, dep.name, dep.manifest)
        if key in seen:
            continue
        seen.add(key)
        hit = lookalike(dep.ecosystem, dep.name)
        if hit:
            real, how = hit
            registry = "npm" if dep.ecosystem == "npm" else "PyPI"
            findings.append(
                _finding(
                    dep,
                    "typosquat-lookalike",
                    f"Dependency '{dep.name}' looks like the popular {registry} package '{real}' ({how})",
                    Severity.MEDIUM,
                    "medium",
                    f"'{dep.name}' {how} compared with '{real}', one of the most-used {registry} "
                    "packages. Typosquats copy popular names to get installed by mistake.",
                    f"If you meant '{real}', fix the name and reinstall. If '{dep.name}' is "
                    "intentional, check its publisher, repository and age before trusting it.",
                )
            )
    metadata: dict[str, object] = {"dependencies_checked": len(seen)}
    if registry_check_enabled() and not network_disabled():
        findings += _registry_findings(root, deps, metadata)
    elif registry_check_enabled():
        metadata["registry_check"] = "skipped: network disabled"
    return findings, metadata


def _registry_findings(
    root: Path, deps: list[Dependency], metadata: dict[str, object]
) -> list[Finding]:
    candidates: dict[tuple[str, str], Dependency] = {}
    skipped: set[str] = set()
    for dep in deps:
        ecosystem_names = popular(dep.ecosystem)
        normalised = _pep503(dep.name) if dep.ecosystem == "pypi" else dep.name.lower()
        if normalised in ecosystem_names:
            continue  # popular packages exist and aren't new
        if dep.ecosystem in skipped or uses_private_registry(root, dep.ecosystem):
            skipped.add(dep.ecosystem)
            continue
        candidates.setdefault((dep.ecosystem, normalised), dep)
    lookups = list(candidates.items())[:_MAX_REGISTRY_LOOKUPS]
    metadata["registry_check"] = {
        "looked_up": len(lookups),
        "private_registry_skipped": sorted(skipped),
    }
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            statuses = list(
                pool.map(lambda item: registry_status(item[0][0], item[1].name), lookups)
            )
    except (OSError, ValueError, urllib.error.URLError) as exc:
        metadata["registry_check"] = f"skipped: network unavailable ({exc})"
        return []
    findings = []
    now = datetime.now(timezone.utc)
    for ((ecosystem, _), dep), (exists, created) in zip(lookups, statuses):
        registry = "npm" if ecosystem == "npm" else "PyPI"
        if not exists:
            findings.append(
                _finding(
                    dep,
                    "dependency-not-on-registry",
                    f"Dependency '{dep.name}' does not exist on {registry}",
                    Severity.HIGH,
                    "medium",
                    f"'{dep.name}' isn't published on {registry}. Names an AI assistant made up "
                    "are registered by attackers ('slopsquatting'): the next install would pull "
                    "their code. If it's a private package, configure your private registry.",
                    "Remove the dependency or replace it with the package you meant. Never "
                    "install a name you can't find on the registry and in its documentation.",
                )
            )
        elif created and (now - created).days < _NEW_PACKAGE_DAYS:
            findings.append(
                _finding(
                    dep,
                    "dependency-recently-published",
                    f"Dependency '{dep.name}' was first published {(now - created).days} day(s) ago — review",
                    Severity.MEDIUM,
                    "low",
                    f"'{dep.name}' first appeared on {registry} on {created.date()}. New packages "
                    "are a common way to ship malware; check the publisher and source.",
                    "Pin an exact version, review the package source and maintainer, or wait.",
                )
            )
    return findings


async def run_typosquat_check(target: str) -> ScanResult:
    result = ScanResult(tool=TOOL_NAME, scan_type=ScanType.SCA, target=target)
    findings, metadata = await asyncio.to_thread(typosquat_findings, target)
    result.findings.extend(findings)
    result.metadata.update(metadata)
    return result
