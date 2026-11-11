"""Java / Kotlin dependencies (Maven, Gradle) without Trivy or a JVM.

Parses ``pom.xml``, ``gradle.lockfile``, ``build.gradle`` / ``build.gradle.kts`` and Gradle
version catalogs (``libs.versions.toml``) into OSV ``Maven`` packages (``group:artifact``).
Only literal versions are used: nothing is resolved from a repository and no build runs.

The packages feed two checks:
- the known-malicious check in ``malicious_packages`` (OSV ``MAL-`` records), and
- ``run_java_dependency_check`` below: known vulnerabilities (CVE / GHSA) from OSV, used when
  Trivy is not installed (Trivy already covers Maven and Gradle lockfiles).
"""

from __future__ import annotations

import asyncio
import json
import re
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from argus.models import Finding, ScanResult, ScanType, Severity
from argus.tools import malicious_packages as mp
from argus.tools.malicious_packages import Package
from argus.utils import is_tool_available

TOOL_NAME = "osv-maven"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
_MAX_DETAIL_LOOKUPS = 400
_LITERAL_VERSION = re.compile(r"^[\w.+-]+$")


def _package(group: str, artifact: str, version: str) -> Package:
    return Package("Maven", f"{group.strip()}:{artifact.strip()}", version.strip())


def _literal(version: str | None) -> str | None:
    """A concrete version, or None for ranges (``[1.0,2.0)``), dynamic (``1.+``) or unresolved."""
    if not version:
        return None
    version = version.strip()
    if not _LITERAL_VERSION.match(version) or "+" in version or version.endswith("SNAPSHOT"):
        return None
    return version


# ── pom.xml ───────────────────────────────────────────────────────────────────


def _strip_namespaces(root: ET.Element) -> None:
    for element in root.iter():
        if isinstance(element.tag, str) and "}" in element.tag:
            element.tag = element.tag.split("}", 1)[1]


def pom_packages(text: str) -> Iterator[Package]:
    # A pom never needs a DTD; refusing them avoids entity-expansion tricks in hostile repos.
    if re.search(r"<!(?:DOCTYPE|ENTITY)", text, re.IGNORECASE):
        return
    root = ET.fromstring(text)
    _strip_namespaces(root)
    props: dict[str, str] = {}
    for prop in root.findall("properties/*"):
        if prop.text:
            props[prop.tag] = prop.text.strip()
    project_version = root.findtext("version") or root.findtext("parent/version")
    if project_version:
        props.setdefault("project.version", project_version.strip())

    def resolve(value: str | None) -> str | None:
        if value is None:
            return None
        for _ in range(5):  # nested ${a} -> ${b} -> 1.0
            match = re.fullmatch(r"\$\{([^}]+)\}", value.strip())
            if not match:
                break
            value = props.get(match.group(1))
            if value is None:
                return None
        return _literal(value)

    for path in ("dependencies/dependency", "dependencyManagement/dependencies/dependency"):
        for dep in root.findall(path):
            group, artifact = dep.findtext("groupId"), dep.findtext("artifactId")
            version = resolve(dep.findtext("version"))
            if group and artifact and version and "${" not in group + artifact:
                yield _package(group, artifact, version)


# ── Gradle ────────────────────────────────────────────────────────────────────

_LOCK_LINE = re.compile(r"^([\w.-]+):([\w.-]+):([^=\s]+)=", re.MULTILINE)
_CONFIGURATIONS = (
    r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly"
    r"|testCompileOnly|annotationProcessor|kapt|ksp|classpath|compile|testCompile|runtime)"
)
_GRADLE_STRING = re.compile(
    r"\b" + _CONFIGURATIONS + r"\s*\(?\s*[\"']([\w.-]+):([\w.-]+):([\w.+-]+)(?::[\w.-]+)?[\"']"
)
_GRADLE_MAP = re.compile(
    r"\b" + _CONFIGURATIONS + r"\s*\(?\s*group\s*[:=]\s*[\"']([\w.-]+)[\"']\s*,\s*"
    r"name\s*[:=]\s*[\"']([\w.-]+)[\"']\s*,\s*version\s*[:=]\s*[\"']([\w.+-]+)[\"']"
)


def gradle_lockfile_packages(text: str) -> Iterator[Package]:
    for group, artifact, version in _LOCK_LINE.findall(text):
        if _literal(version):
            yield _package(group, artifact, version)


def gradle_build_packages(text: str) -> Iterator[Package]:
    for pattern in (_GRADLE_STRING, _GRADLE_MAP):
        for group, artifact, version in pattern.findall(text):
            if _literal(version):
                yield _package(group, artifact, version)


def version_catalog_packages(text: str) -> Iterator[Package]:
    if mp._toml is None:
        return
    data = mp._toml.loads(text)
    versions = data.get("versions", {}) if isinstance(data.get("versions"), dict) else {}
    libraries = data.get("libraries", {})
    if not isinstance(libraries, dict):
        return
    for entry in libraries.values():
        if isinstance(entry, str):
            parts = entry.split(":")
            if len(parts) == 3 and _literal(parts[2]):
                yield _package(parts[0], parts[1], parts[2])
            continue
        if not isinstance(entry, dict):
            continue
        module = entry.get("module")
        group: object
        artifact: object
        if isinstance(module, str) and ":" in module:
            group, artifact = module.split(":", 1)
        else:
            group, artifact = entry.get("group"), entry.get("name")
        version = entry.get("version")
        if isinstance(version, dict):  # version.ref = "x" / version = { strictly = "1.0" }
            ref = version.get("ref")
            version = versions.get(ref) if isinstance(ref, str) else version.get("strictly")
        if isinstance(group, str) and isinstance(artifact, str) and isinstance(version, str):
            if _literal(version):
                yield _package(group, artifact, version)


MAVEN_PARSERS = {
    "pom.xml": pom_packages,
    "gradle.lockfile": gradle_lockfile_packages,
    "build.gradle": gradle_build_packages,
    "build.gradle.kts": gradle_build_packages,
    "libs.versions.toml": version_catalog_packages,
}


# ── Known vulnerabilities (CVE / GHSA) ────────────────────────────────────────

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


def _fetch_vuln(vuln_id: str) -> dict[str, Any]:
    url = OSV_VULN_URL + urllib.parse.quote(vuln_id)
    request = urllib.request.Request(url, headers={"User-Agent": "argus-scan"})
    with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 (fixed https URL)
        data = json.loads(response.read().decode("utf-8"))
    return data if isinstance(data, dict) else {}


def _fixed_versions(details: dict[str, Any], name: str) -> list[str]:
    fixed: set[str] = set()
    for affected in details.get("affected", []) or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package", {})
        if isinstance(package, dict) and package.get("name") != name:
            continue
        for rng in affected.get("ranges", []) or []:
            for event in (rng or {}).get("events", []) or []:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed.add(event["fixed"])
    return sorted(fixed)


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", version)[:4])


def _upgrade_targets(current: str, fixed: list[str]) -> list[str]:
    """The nearest fixed version above ``current`` (advisories list one per release line)."""
    newer = [v for v in fixed if _version_key(v) > _version_key(current)]
    return [min(newer, key=_version_key)] if newer else fixed


def _vulnerability_finding(
    package: Package, vuln_id: str, details: dict[str, Any], lockfile: str, line: int
) -> Finding:
    label = str((details.get("database_specific") or {}).get("severity", "")).lower()
    severity = _SEVERITY.get(label, Severity.HIGH)
    aliases = [a for a in details.get("aliases", []) or [] if isinstance(a, str)]
    cves = [a for a in aliases if a.startswith("CVE-")]
    summary = str(details.get("summary") or "").strip() or f"Known vulnerability {vuln_id}"
    fixed = _upgrade_targets(package.version, _fixed_versions(details, package.name))
    return Finding(
        title=f"{package.name}@{package.version}: {summary}",
        severity=severity,
        scan_type=ScanType.SCA,
        tool=TOOL_NAME,
        file=lockfile,
        line=line,
        rule_id=vuln_id,
        cve=", ".join(cves),
        confidence="high",
        description=f"OSV lists {vuln_id}"
        + (f" ({', '.join(cves)})" if cves else "")
        + f" for Maven package {package.name} {package.version}.",
        fix_guidance=(
            f"Upgrade {package.name} to {' or '.join(fixed)} or later."
            if fixed
            else f"Upgrade {package.name}; see the advisory for patched versions."
        ),
        references=[f"https://osv.dev/vulnerability/{vuln_id}"],
    )


def _fetch_all(vuln_ids: list[str]) -> dict[str, dict[str, Any]]:
    with ThreadPoolExecutor(max_workers=8) as pool:
        return dict(zip(vuln_ids, pool.map(_fetch_vuln, vuln_ids)))


async def run_java_dependency_check(target: str) -> ScanResult:
    """Known CVEs in Maven / Gradle dependencies via OSV (skipped when Trivy is installed)."""
    result = ScanResult(tool=TOOL_NAME, scan_type=ScanType.SCA, target=target)
    collected, _lockfiles, errors = await asyncio.to_thread(mp.collect_packages, Path(target))
    maven = {p: locs for p, locs in collected.items() if p.ecosystem == "Maven"}
    result.errors.extend(e for e in errors if any(n in e for n in MAVEN_PARSERS))
    result.metadata["packages_checked"] = len(maven)
    if not maven:
        return result
    if is_tool_available("trivy"):
        result.metadata["skipped"] = "Trivy is installed and covers Maven / Gradle"
        return result
    if mp.network_disabled():
        result.metadata["skipped"] = "network disabled (ARGUS_NO_NETWORK / --no-network)"
        return result
    try:
        ids_by_package = await asyncio.to_thread(mp.query_vulnerability_ids, list(maven))
        # MAL- records are reported by the known-malicious check.
        ids_by_package = {
            p: [i for i in ids if not i.startswith("MAL-")] for p, ids in ids_by_package.items()
        }
        unique_ids = sorted({i for ids in ids_by_package.values() for i in ids})
        lookups = unique_ids[:_MAX_DETAIL_LOOKUPS]
        details = await asyncio.to_thread(_fetch_all, lookups)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        result.errors.append(f"OSV Maven vulnerability check skipped: network unavailable ({exc})")
        return result
    if len(unique_ids) > len(lookups):
        result.errors.append(
            f"{len(unique_ids) - len(lookups)} more advisories were not looked up (limit {_MAX_DETAIL_LOOKUPS})"
        )
    for package in sorted(ids_by_package, key=lambda p: p.name):
        for vuln_id in ids_by_package[package]:
            if vuln_id not in details:
                continue
            for lockfile, line in maven[package]:
                result.findings.append(
                    _vulnerability_finding(package, vuln_id, details[vuln_id], lockfile, line)
                )
    return result
