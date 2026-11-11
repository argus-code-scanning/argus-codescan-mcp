"""Extract remote dependency sources without fetching or executing manifests."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from argus_languages.models import Finding
from argus_languages.rules_loader import LoadedRule

MANIFEST_LANGUAGES = frozenset(
    {"npm-manifest", "python-requirements", "python-manifest", "composer"}
)
_SHA = re.compile(r"[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?\Z")
_GIT = re.compile(r"^(?:git\+|git://|ssh://|git@|github:|gitlab:|bitbucket:)|\.git(?:[#@]|$)")
_SHORTHAND = re.compile(r"^[\w.-]+/[\w.-]+(?:#.*)?$")


@dataclass(frozen=True)
class DependencySource:
    name: str
    value: str
    location: str
    git: bool = False


def _direct(name: str, value: object) -> Iterator[DependencySource]:
    if not isinstance(value, str):
        return
    source = value.strip()
    if " @ " in source:
        source = source.split(" @ ", 1)[1].strip()
    yield DependencySource(name, source, value)


def _poetry(name: str, spec: object) -> Iterator[DependencySource]:
    if not isinstance(spec, dict):
        return
    if isinstance(spec.get("git"), str):
        url = spec["git"]
        ref = spec.get("rev") or spec.get("tag") or spec.get("branch")
        yield DependencySource(name, url + (f"@{ref}" if ref else ""), url, git=True)
    elif isinstance(spec.get("url"), str):
        yield from _direct(name, spec["url"])


def _python_manifest(data: dict) -> Iterator[DependencySource]:
    project = data.get("project", {})
    if isinstance(project, dict):
        groups = [project.get("dependencies", [])]
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            groups.extend(optional.values())
        for group in groups:
            if isinstance(group, list):
                for value in group:
                    if isinstance(value, str):
                        yield from _direct(value.split(" @ ", 1)[0], value)
    groups = data.get("dependency-groups", {})
    if isinstance(groups, dict):
        for group in groups.values():
            if isinstance(group, list):
                for value in group:
                    if isinstance(value, str):
                        yield from _direct(value.split(" @ ", 1)[0], value)
    tool = data.get("tool", {})
    poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
    if isinstance(poetry, dict):
        tables = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})]
        groups = poetry.get("group", {})
        if isinstance(groups, dict):
            tables.extend(g.get("dependencies", {}) for g in groups.values() if isinstance(g, dict))
        for table in tables:
            if isinstance(table, dict):
                for name, value in table.items():
                    for spec in value if isinstance(value, list) else [value]:
                        yield from _poetry(name, spec)


def _composer(data: dict) -> Iterator[DependencySource]:
    repositories = data.get("repositories", [])
    if isinstance(repositories, dict):
        repositories = list(repositories.values())
    if not isinstance(repositories, list):
        return
    for repo in repositories:
        if not isinstance(repo, dict):
            continue
        if isinstance(repo.get("url"), str) and not (
            repo.get("type") == "composer" and repo["url"].lower().startswith("https://")
        ):
            yield DependencySource(
                "repository", repo["url"], repo["url"], repo.get("type") == "vcs"
            )
        packages = repo.get("package", [])
        if isinstance(packages, dict):
            packages = [packages]
        if not isinstance(packages, list):
            continue
        for package in packages:
            if not isinstance(package, dict):
                continue
            for kind in ("dist", "source"):
                spec = package.get(kind, {})
                if not isinstance(spec, dict) or not isinstance(spec.get("url"), str):
                    continue
                url = spec["url"]
                git = kind == "source" and spec.get("type") == "git"
                ref = spec.get("reference") if git else None
                yield DependencySource(
                    str(package.get("name", "package")), url + (f"@{ref}" if ref else ""), url, git
                )


def dependency_sources(language: str, content: str) -> list[DependencySource]:
    """Read dependency fields only, ignoring metadata URLs and malformed manifests."""
    if language == "python-requirements":
        out: list[DependencySource] = []
        for logical in content.replace("\\\n", " ").splitlines():
            value = logical.strip()
            if not value or value.startswith("#"):
                continue
            value = re.sub(r"^(?:-e\s+|--editable(?:=|\s+))", "", value)
            if value.startswith("-"):
                continue
            # A fragment belongs to the URL; only whitespace-prefixed # starts a comment.
            value = re.split(r"\s+#|\s+--hash=|\s*;", value, maxsplit=1)[0].strip()
            out.extend(_direct(value.split(" @ ", 1)[0], value))
        return out
    try:
        data = tomllib.loads(content) if language == "python-manifest" else json.loads(content)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    if language == "npm-manifest":
        out = []
        for section in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            table = data.get(section, {})
            if isinstance(table, dict):
                for name, value in table.items():
                    out.extend(_direct(name, value))
        return out
    if language == "python-manifest":
        return list(_python_manifest(data))
    if language == "composer":
        return list(_composer(data))
    return []


def _risk(source: DependencySource) -> str | None:
    value = source.value
    if re.match(r"^(?:git\+)?http://", value, re.I):
        return "http"
    is_git = source.git or bool(_GIT.search(value)) or bool(_SHORTHAND.fullmatch(value))
    if is_git:
        # npm uses #ref; pip/Poetry use @ref before optional #egg/subdirectory fragments.
        ref = value.rsplit("#", 1)[-1] if "#" in value else ""
        if not _SHA.fullmatch(ref):
            without_fragment = value.split("#", 1)[0]
            tail = without_fragment.rsplit("/", 1)[-1]
            ref = tail.rsplit("@", 1)[-1] if "@" in tail else ""
        return None if _SHA.fullmatch(ref) else "git-unpinned"
    if value.lower().startswith("https://"):
        return "https"
    return None


def scan_dependency_sources(
    relative: str, language: str, content: str, rules: list[LoadedRule]
) -> list[Finding]:
    """Apply dependency-source rules to parsed source types, never arbitrary prose."""
    if language not in MANIFEST_LANGUAGES:
        return []
    selected = [r for r in rules if r.languages and "dependency-source" in r.languages]
    if not selected:
        return []
    findings = []
    seen = set()
    for source in dependency_sources(language, content):
        risk = _risk(source)
        if not risk:
            continue
        # JSON may escape slashes; prefer a literal source, then its encoded form.
        position = content.find(source.location)
        if position < 0:
            position = content.find(json.dumps(source.location, ensure_ascii=False)[1:-1])
        line = content.count("\n", 0, max(0, position)) + 1
        for rule in selected:
            if not rule.pattern.fullmatch(risk) or (rule.id, line, source.name) in seen:
                continue
            seen.add((rule.id, line, source.name))
            findings.append(
                Finding(
                    title=rule.title,
                    severity=rule.severity,
                    tool="argus-languages",
                    file=relative,
                    line=line,
                    rule_id=rule.id,
                    language=language,
                    confidence=rule.confidence,
                    description="Review the remote dependency source. No network request was made.",
                    fix_guidance=rule.fix_guidance,
                )
            )
    return findings
