"""SCA (Software Composition Analysis) tool runners.

Integrates: Trivy (filesystem mode), Safety (Python), pip-audit (Python),
            npm audit (Node.js), govulncheck (Go), composer audit (PHP), and a built-in
            check of lockfile packages against OSV known-malicious (MAL-) records.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from argus.models import Finding, ScanResult, ScanType, Severity
from argus.tools.dep_graph import read_graph
from argus.utils import (
    collect_scan_results,
    find_scan_files,
    is_tool_available,
    parse_json_output,
    run_command,
)

logger = logging.getLogger(__name__)

TRIVY_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.UNKNOWN,
}


async def run_trivy_fs(
    target: str,
    timeout: int = 300,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Run Trivy filesystem scan for dependency vulnerabilities."""
    result = ScanResult(tool="trivy", scan_type=ScanType.SCA, target=target)

    if not is_tool_available("trivy"):
        result.tool_available = False
        result.errors.append(
            "trivy is not installed. See https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
        )
        return result

    cmd = [
        "trivy",
        "fs",
        "--format",
        "json",
        "--exit-code",
        "0",
        "--scanners",
        "vuln,secret",
        target,
    ]
    if extra_args:
        cmd.extend(extra_args)

    code, stdout, stderr = await run_command(cmd, timeout=timeout)
    result.raw_output = stdout

    data = parse_json_output(stdout)
    if not data:
        if stderr:
            result.errors.append(f"Trivy error: {stderr[:500]}")
        return result

    for report in data.get("Results", []):
        target_file = report.get("Target", "")
        for vuln in report.get("Vulnerabilities", []) or []:
            sev_str = vuln.get("Severity", "UNKNOWN").upper()
            severity = TRIVY_SEVERITY_MAP.get(sev_str, Severity.UNKNOWN)

            finding = Finding(
                title=vuln.get("VulnerabilityID", ""),
                severity=severity,
                scan_type=ScanType.SCA,
                tool="trivy",
                file=target_file,
                description=vuln.get("Description", vuln.get("Title", "")),
                cve=vuln.get("VulnerabilityID", ""),
                fix_guidance=f"Fix version: {vuln.get('FixedVersion', 'N/A')}",
                references=vuln.get("References", [])[:5],
                rule_id=vuln.get("VulnerabilityID", ""),
                raw=vuln,
            )
            # Add package info to description
            pkg_name = vuln.get("PkgName", "")
            installed = vuln.get("InstalledVersion", "")
            if pkg_name:
                finding.description = f"{pkg_name}@{installed}: {finding.description}"
            result.findings.append(finding)

        # Secret findings from Trivy
        for secret in report.get("Secrets", []) or []:
            sev_str = secret.get("Severity", "HIGH").upper()
            severity = TRIVY_SEVERITY_MAP.get(sev_str, Severity.HIGH)
            finding = Finding(
                title=secret.get("RuleID", "secret-detected"),
                severity=severity,
                scan_type=ScanType.SECRETS,
                tool="trivy-secrets",
                file=target_file,
                line=secret.get("StartLine", 0),
                description=secret.get("Title", ""),
                rule_id=secret.get("RuleID", ""),
                raw=secret,
            )
            result.findings.append(finding)

    return result


async def run_safety(
    target: str,
    timeout: int = 120,
) -> ScanResult:
    """Run Safety to check Python dependencies for known vulnerabilities."""
    result = ScanResult(tool="safety", scan_type=ScanType.SCA, target=target)

    if not is_tool_available("safety"):
        result.tool_available = False
        result.errors.append("safety is not installed. Install with: pip install safety")
        return result

    target_path = Path(target)
    req_files = (
        (find_scan_files(target_path, "requirements*.txt", "Pipfile.lock", "poetry.lock"))
        if target_path.is_dir()
        else [target_path]
    )

    all_findings: list[Finding] = []

    for req_file in req_files[:5]:  # Limit to 5 files
        cmd = [
            "safety",
            "check",
            "--json",
            "--file",
            str(req_file),
        ]
        code, stdout, stderr = await run_command(cmd, timeout=timeout)

        data = parse_json_output(stdout)
        if not data:
            continue

        vulns = (
            data
            if isinstance(data, list)
            else data.get("vulnerabilities", data.get("affected_packages", []))
        )
        if not isinstance(vulns, list):
            continue

        for vuln in vulns:
            if isinstance(vuln, list) and len(vuln) >= 5:
                # Legacy format: [package, spec, installed, advisory, vuln_id]
                finding = Finding(
                    title=vuln[4] if len(vuln) > 4 else "safety-vuln",
                    severity=Severity.HIGH,
                    scan_type=ScanType.SCA,
                    tool="safety",
                    file=str(req_file),
                    description=vuln[3] if len(vuln) > 3 else "",
                    rule_id=str(vuln[4]) if len(vuln) > 4 else "",
                    raw={"data": vuln},
                )
            elif isinstance(vuln, dict):
                sev = vuln.get("severity", {})
                sev_str = (
                    (sev.get("cvssv3", {}).get("base_severity") or "HIGH").upper()
                    if isinstance(sev, dict)
                    else "HIGH"
                )
                severity = TRIVY_SEVERITY_MAP.get(sev_str, Severity.HIGH)
                finding = Finding(
                    title=str(
                        vuln.get("vulnerability_id", vuln.get("id", "safety-vuln")) or "safety-vuln"
                    ),
                    severity=severity,
                    scan_type=ScanType.SCA,
                    tool="safety",
                    file=str(req_file),
                    description=str(vuln.get("advisory", vuln.get("description", "")) or ""),
                    cve=vuln.get("cve", ""),
                    rule_id=vuln.get("vulnerability_id", ""),
                    raw=vuln,
                )
            else:
                continue

            all_findings.append(finding)

    result.findings = all_findings
    return result


# Advisory severities as reported by npm, Composer and OSV (GHSA ``database_specific``).
ADVISORY_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

OSV_API_URL = "https://api.osv.dev/v1/vulns"
_osv_severity_cache: dict[str, Severity | None] = {}


def _osv_severity(vuln_id: str) -> Severity | None:
    """Look up an advisory's severity on OSV (best effort, cached)."""
    if vuln_id in _osv_severity_cache:
        return _osv_severity_cache[vuln_id]
    severity: Severity | None = None
    try:
        url = f"{OSV_API_URL}/{urllib.parse.quote(vuln_id)}"
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
        label = str(data.get("database_specific", {}).get("severity", "")).lower()
        severity = ADVISORY_SEVERITY_MAP.get(label)
    except (OSError, ValueError):
        pass
    _osv_severity_cache[vuln_id] = severity
    return severity


async def _advisory_severity(ids: list[str], default: Severity = Severity.HIGH) -> Severity:
    """Resolve severity via OSV, preferring GHSA ids (they carry a severity label).

    Falls back to ``default`` (HIGH) so ``--fail-on high`` stays conservative offline.
    """
    for vuln_id in sorted(ids, key=lambda i: not i.startswith("GHSA-")):
        severity = await asyncio.to_thread(_osv_severity, vuln_id)
        if severity is not None:
            return severity
    return default


def _manifest_dirs(target_path: Path, manifest: str) -> list[Path]:
    """Directories under ``target_path`` that contain ``manifest`` (sorted, deduplicated)."""
    if target_path.is_file():
        return [target_path.parent] if target_path.name == manifest else []
    return sorted({path.parent for path in find_scan_files(target_path, manifest)})


async def run_pip_audit(
    target: str,
    timeout: int = 120,
) -> ScanResult:
    """Run pip-audit on every requirements file and Python project under ``target``.

    Never audits the environment Argus itself runs in: that would report
    Argus's dependencies as findings in the scanned project.
    """
    result = ScanResult(tool="pip-audit", scan_type=ScanType.SCA, target=target)

    if not is_tool_available("pip-audit"):
        result.tool_available = False
        result.errors.append("pip-audit is not installed. Install with: pip install pip-audit")
        return result

    target_path = Path(target)
    if target_path.is_file():
        req_files = [target_path] if target_path.suffix == ".txt" else []
    else:
        req_files = sorted(find_scan_files(target_path, "requirements*.txt"))
    projects = _manifest_dirs(target_path, "pyproject.toml")

    base = ["pip-audit", "--format", "json", "--aliases", "on", "--progress-spinner", "off"]
    jobs: list[tuple[Path, list[str]]] = [(f, [*base, "-r", str(f)]) for f in req_files]
    jobs += [(d / "pyproject.toml", [*base, str(d)]) for d in projects]

    outputs = await asyncio.gather(*(run_command(cmd, timeout=timeout) for _, cmd in jobs))
    for (manifest, _), (_code, stdout, stderr) in zip(jobs, outputs, strict=True):
        result.raw_output += stdout
        data = parse_json_output(stdout)
        if not isinstance(data, dict | list):
            result.errors.append(f"pip-audit failed for {manifest}: {stderr.strip()[-400:]}")
            continue
        deps = data if isinstance(data, list) else data.get("dependencies", [])
        for dep in deps:
            pkg, ver = dep.get("name", ""), dep.get("version", "")
            for vuln in dep.get("vulns", []):
                vuln_id = vuln.get("id", "pip-audit-vuln")
                ids = [vuln_id, *vuln.get("aliases", [])]
                fixes = vuln.get("fix_versions") or []
                result.findings.append(
                    Finding(
                        title=f"{pkg}@{ver}: {vuln_id}",
                        severity=await _advisory_severity(ids),
                        scan_type=ScanType.SCA,
                        tool="pip-audit",
                        file=str(manifest),
                        description=f"{pkg}@{ver}: {vuln.get('description', '')}".strip(),
                        cve=next((i for i in ids if i.startswith("CVE-")), vuln_id),
                        fix_guidance=(
                            f"Upgrade {pkg} to {', '.join(fixes)}"
                            if fixes
                            else "No fixed version published yet"
                        ),
                        rule_id=vuln_id,
                        references=[f"https://osv.dev/vulnerability/{vuln_id}"],
                        raw=vuln,
                    )
                )

    return result


NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")


def _version_key(version: str) -> tuple[int, int, int]:
    parts = re.split(r"[.+-]", re.sub(r"^[^\d]*", "", version))[:3]
    nums = [int(p) if p.isdigit() else 0 for p in parts]
    return (nums + [0, 0, 0])[0], (nums + [0, 0, 0])[1], (nums + [0, 0, 0])[2]


def _npm_fix_guidance(
    fix: object,
    package: str = "",
    affected: str = "",
    installed: dict[str, list[str]] | None = None,
) -> str:
    """What to do, from npm audit's ``fixAvailable``.

    npm sometimes "fixes" an advisory by moving a direct dependency to an older major
    version; that is called out instead of passed on. Same text as the npm scanner.
    """
    in_range = f" (affected: {affected})" if affected else ""
    if fix is True:
        return "Run npm audit fix (no breaking changes)."
    if not isinstance(fix, dict) or not fix.get("name") or not fix.get("version"):
        return (
            f"No patched version of {package} is published yet{in_range}. "
            'Update it when one is, or pin it with "overrides".'
        )
    name, version = str(fix["name"]), str(fix["version"])
    versions = sorted((installed or {}).get(name, []), key=_version_key)
    if versions and _version_key(version) < _version_key(versions[-1]):
        return (
            f"No safe fix yet: npm audit fix --force would downgrade {name} {versions[-1]} to "
            f"{version}. Don't run it; wait for a patched {package}{in_range} and pin it with "
            '"overrides".'
        )
    major = " (major version: check for breaking changes)" if fix.get("isSemVerMajor") else ""
    return f"Upgrade {name} to {version}{major}."


def _npm_installed_versions(lockfile: Path) -> dict[str, list[str]]:
    """Installed versions from package-lock.json, keyed by name and by lockfile path."""
    try:
        data = json.loads(lockfile.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    found: dict[str, set[str]] = {}

    def add(name: str, version: object) -> None:
        if isinstance(version, str) and not version.startswith("file:"):
            found.setdefault(name, set()).add(version)

    for key, entry in (data.get("packages") or {}).items():
        at = key.rfind("node_modules/")
        if at < 0 or not isinstance(entry, dict):
            continue
        add(entry.get("name") or key[at + len("node_modules/") :], entry.get("version"))
        add(key, entry.get("version"))
    return {name: sorted(versions) for name, versions in found.items()}


def _npm_dependency_paths(
    vulnerabilities: dict[str, Any], package: str, runtime: set[str]
) -> list[str]:
    """Every way ``package`` is installed, from a direct dependency down (npm audit ``effects``).

    Runtime paths come first, then shorter ones: ["typeorm › tinyglobby › picomatch", ...].
    """
    paths: list[list[str]] = []
    queue: list[list[str]] = [[package]]
    reached: set[str] = set()
    while queue and len(paths) < 50:
        chain = queue.pop(0)
        entry = vulnerabilities.get(chain[0]) or {}
        if entry.get("isDirect") and chain[0] not in reached:
            reached.add(chain[0])
            paths.append(chain)
        for parent in entry.get("effects") or []:
            if parent not in chain and len(chain) < 8:
                queue.append([parent, *chain])
    paths.sort(key=lambda c: (c[0] not in runtime, len(c), c[0]))
    return [" \u203a ".join(chain) for chain in paths]


def _npm_count_note(data: dict[str, Any], findings: list[Finding]) -> str:
    """npm audit counts every vulnerable package, including ones that only depend on another."""
    meta_total = ((data.get("metadata") or {}).get("vulnerabilities") or {}).get("total")
    total = meta_total if isinstance(meta_total, int) else len(data.get("vulnerabilities") or {})
    packages = len({f.package for f in findings})
    if not findings or total <= packages:
        return ""
    advisories = len({(f.package, f.rule_id) for f in findings})
    return (
        f"{advisories} {'advisory' if advisories == 1 else 'advisories'} in {packages} "
        f"{'package' if packages == 1 else 'packages'}. npm audit reports {total} vulnerable "
        "packages because it also counts every package that depends on one; those are listed "
        'under "via".'
    )


_DEV_DOWNGRADE = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFO,
}


def _scoped(severity: Severity, scope: str) -> tuple[Severity, str]:
    """Dev-only packages don't ship: lower one level and tag them, like findings in tests."""
    if scope == "dev":
        return _DEV_DOWNGRADE.get(severity, severity), "dev-dependency"
    return severity, ""


async def run_npm_audit(
    target: str,
    timeout: int = 120,
) -> ScanResult:
    """Run npm audit in every npm project (package.json + lockfile) under ``target``.

    Emits one finding per advisory and marks whether the vulnerable package is a
    runtime or dev-only dependency.
    """
    result = ScanResult(tool="npm-audit", scan_type=ScanType.SCA, target=target)

    if not is_tool_available("npm"):
        result.tool_available = False
        result.errors.append("npm is not installed or not on PATH.")
        return result

    target_path = Path(target)
    if target_path.is_file() and target_path.name in (*NPM_LOCKFILES, "package.json"):
        target_path = target_path.parent
    package_dirs = _manifest_dirs(target_path, "package.json")
    projects = [d for d in package_dirs if any((d / lock).exists() for lock in NPM_LOCKFILES)]
    if not package_dirs:
        result.errors.append("No package.json found in target")
        return result
    # Workspace members share the root lockfile; only flag packages nothing covers.
    unlocked = [d for d in package_dirs if not any(d == p or p in d.parents for p in projects)]
    if unlocked:
        result.errors.append(
            "npm audit needs a lockfile; skipped (run npm install to create one): "
            + ", ".join(str(d) for d in unlocked)
        )

    for project in projects:
        lockfile = next(project / lock for lock in NPM_LOCKFILES if (project / lock).exists())
        (_, stdout, stderr), (_, prod_stdout, _) = await asyncio.gather(
            run_command(["npm", "audit", "--json"], cwd=str(project), timeout=timeout),
            run_command(
                ["npm", "audit", "--json", "--omit=dev"], cwd=str(project), timeout=timeout
            ),
        )
        result.raw_output += stdout
        data = parse_json_output(stdout)
        if not isinstance(data, dict) or "error" in data:
            detail = data.get("error", {}).get("summary") if isinstance(data, dict) else None
            result.errors.append(f"npm audit failed in {project}: {detail or stderr[:400]}")
            continue
        prod = parse_json_output(prod_stdout)
        runtime = set(prod.get("vulnerabilities", {})) if isinstance(prod, dict) else set()

        seen: set[tuple[str, str]] = set()
        installed = _npm_installed_versions(lockfile)
        vulnerabilities = data.get("vulnerabilities", {})
        project_findings: list[Finding] = []
        for name, info in vulnerabilities.items():
            # String entries in ``via`` point at another vulnerable package, which
            # carries the advisory itself; only advisory objects become findings.
            for via in info.get("via", []):
                if not isinstance(via, dict):
                    continue
                url = via.get("url", "")
                advisory = url.rsplit("/", 1)[-1] if "GHSA-" in url else str(via.get("source", ""))
                if (name, advisory) in seen:
                    continue
                seen.add((name, advisory))
                scope = "runtime" if name in runtime else "dev"
                title = via.get("title", "")
                cwes = via.get("cwe") or []
                sev = str(via.get("severity") or info.get("severity", "moderate")).lower()
                severity, context = _scoped(ADVISORY_SEVERITY_MAP.get(sev, Severity.MEDIUM), scope)
                nodes = info.get("nodes") or []
                versions = sorted(
                    {v for n in nodes for v in installed.get(n, [])}
                ) or installed.get(name, [])
                project_findings.append(
                    Finding(
                        title=(
                            title
                            if title.lower().startswith(name.lower())
                            else f"{name}: {title}"
                            if title
                            else name
                        ),
                        severity=severity,
                        context=context,
                        scan_type=ScanType.SCA,
                        tool="npm-audit",
                        file=str(lockfile),
                        description=f"[{scope} dependency] {name} {via.get('range', '')}: {title}",
                        cwe=cwes[0] if cwes else "",
                        cve=advisory,
                        fix_guidance=_npm_fix_guidance(
                            info.get("fixAvailable"), name, via.get("range", ""), installed
                        ),
                        rule_id=advisory,
                        references=[url] if url else [],
                        raw=via,
                        package=name,
                        version=", ".join(versions),
                        dependency_paths=_npm_dependency_paths(vulnerabilities, name, runtime),
                    )
                )
        result.findings.extend(project_findings)
        note = _npm_count_note(data, project_findings)
        if note:
            prefix = f"{lockfile}: " if len(projects) > 1 else ""
            result.metadata.setdefault("notes", []).append(prefix + note)

    return result


def _iter_json_stream(text: str) -> list[dict[str, Any]]:
    """Decode concatenated (possibly pretty-printed) JSON objects."""
    decoder = json.JSONDecoder()
    objects: list[dict[str, Any]] = []
    index = 0
    while True:
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            return objects
        try:
            obj, index = decoder.raw_decode(text, index)
        except ValueError:
            return objects
        if isinstance(obj, dict):
            objects.append(obj)


async def run_govulncheck(
    target: str,
    timeout: int = 300,
) -> ScanResult:
    """Run govulncheck in every Go module under ``target``.

    govulncheck traces call graphs: vulnerabilities in code your module actually
    calls are reported at their advisory severity; ones only present in imported
    or required modules are LOW (visible by default, below --fail-on high).
    """
    result = ScanResult(tool="govulncheck", scan_type=ScanType.SCA, target=target)

    if not is_tool_available("govulncheck") or not is_tool_available("go"):
        result.tool_available = False
        result.errors.append(
            "govulncheck is not installed. Install Go, then: "
            "go install golang.org/x/vuln/cmd/govulncheck@latest"
        )
        return result

    for module in _manifest_dirs(Path(target), "go.mod"):
        _code, stdout, stderr = await run_command(
            ["govulncheck", "-json", "./..."], cwd=str(module), timeout=timeout
        )
        result.raw_output += stdout
        messages = _iter_json_stream(stdout)
        if not messages:
            result.errors.append(f"govulncheck failed in {module}: {stderr.strip()[-400:]}")
            continue

        osv_entries = {m["osv"]["id"]: m["osv"] for m in messages if "osv" in m}
        go_graph = read_graph(module / "go.mod")
        levels = {"required": 0, "imported": 1, "called": 2}
        best: dict[str, tuple[int, dict[str, Any]]] = {}
        for message in messages:
            finding = message.get("finding")
            if not finding:
                continue
            frames = finding.get("trace") or [{}]
            level = (
                "called"
                if frames[0].get("function")
                else "imported"
                if frames[0].get("package")
                else "required"
            )
            current = best.get(finding["osv"])
            if current is None or levels[level] > current[0]:
                best[finding["osv"]] = (levels[level], finding)

        for vuln_id, (level_rank, finding) in sorted(best.items()):
            entry = osv_entries.get(vuln_id, {})
            frames = finding.get("trace") or [{}]
            vulnerable = frames[0]
            called = level_rank == levels["called"]
            # The last frame with a position is the call site in your code.
            position: dict[str, Any] = next(
                (f["position"] for f in reversed(frames) if f.get("position")), {}
            )
            ids = [vuln_id, *entry.get("aliases", [])]
            where = vulnerable.get("package") or vulnerable.get("module", "")
            symbol = f"{where}.{vulnerable['function']}" if called else where
            fixed = finding.get("fixed_version")
            result.findings.append(
                Finding(
                    title=f"{vulnerable.get('module', '')}: {entry.get('summary', vuln_id)}",
                    severity=await _advisory_severity(ids) if called else Severity.LOW,
                    scan_type=ScanType.SCA,
                    tool="govulncheck",
                    file=position.get("filename") or str(module / "go.mod"),
                    line=position.get("line", 0),
                    description=(
                        f"[{'called' if called else 'not called'}] {symbol}@"
                        f"{vulnerable.get('version', '')}: {entry.get('summary', '')}"
                    ),
                    cve=next((i for i in ids if i.startswith("CVE-")), vuln_id),
                    fix_guidance=(
                        f"Upgrade {vulnerable.get('module', '')} to {fixed}"
                        if fixed
                        else "No fixed version published yet"
                    ),
                    rule_id=vuln_id,
                    references=[f"https://pkg.go.dev/vuln/{vuln_id}"],
                    raw=finding,
                    package=vulnerable.get("module", ""),
                    version=vulnerable.get("version", ""),
                    dependency_paths=go_graph.paths_to(vulnerable.get("module", "")),
                )
            )

    return result


def _composer_advisories(data: object) -> list[dict[str, Any]]:
    # PHP encodes an empty map as ``[]``.
    advisories = data.get("advisories") if isinstance(data, dict) else None
    if not isinstance(advisories, dict):
        return []
    return [a for items in advisories.values() for a in items if isinstance(a, dict)]


async def run_composer_audit(
    target: str,
    timeout: int = 120,
) -> ScanResult:
    """Run ``composer audit`` on every composer.lock under ``target``."""
    result = ScanResult(tool="composer-audit", scan_type=ScanType.SCA, target=target)

    if not is_tool_available("composer"):
        result.tool_available = False
        result.errors.append("composer is not installed. See https://getcomposer.org/download/")
        return result

    for project in _manifest_dirs(Path(target), "composer.lock"):
        cmd = ["composer", "audit", "--locked", "--format=json", "--no-interaction"]
        (_, stdout, stderr), (_, prod_stdout, _) = await asyncio.gather(
            run_command(cmd, cwd=str(project), timeout=timeout),
            run_command([*cmd, "--no-dev"], cwd=str(project), timeout=timeout),
        )
        result.raw_output += stdout
        data = parse_json_output(stdout)
        if not isinstance(data, dict):
            result.errors.append(f"composer audit failed in {project}: {stderr.strip()[-400:]}")
            continue
        runtime = {
            a.get("advisoryId") for a in _composer_advisories(parse_json_output(prod_stdout))
        }

        for advisory in _composer_advisories(data):
            pkg = advisory.get("packageName", "")
            advisory_id = advisory.get("advisoryId", "")
            cve = advisory.get("cve") or ""
            scope = "runtime" if advisory_id in runtime else "dev"
            label = str(advisory.get("severity") or "").lower()
            severity = ADVISORY_SEVERITY_MAP.get(label) or await _advisory_severity(
                [cve] if cve else []
            )
            severity, context = _scoped(severity, scope)
            link = advisory.get("link") or ""
            result.findings.append(
                Finding(
                    title=f"{pkg}: {advisory.get('title', advisory_id)}",
                    severity=severity,
                    context=context,
                    package=pkg,
                    scan_type=ScanType.SCA,
                    tool="composer-audit",
                    file=str(project / "composer.lock"),
                    description=(
                        f"[{scope} dependency] {pkg} {advisory.get('affectedVersions', '')}: "
                        f"{advisory.get('title', '')}"
                    ),
                    cve=cve or advisory_id,
                    fix_guidance=f"Upgrade {pkg} outside {advisory.get('affectedVersions', '')}",
                    rule_id=cve or advisory_id,
                    references=[link] if link else [],
                    raw=advisory,
                )
            )

    return result


async def run_all_sca(
    target: str,
    timeout: int = 300,
) -> list[ScanResult]:
    """Run all available SCA tools against a target."""
    from argus.tools.malicious_packages import run_malicious_package_check
    from argus.tools.maven_deps import run_java_dependency_check
    from argus.tools.osv_deps import run_osv_dependency_check
    from argus.tools.typosquats import run_typosquat_check

    tasks = [
        run_trivy_fs(target, timeout=timeout),
        run_safety(target, timeout=timeout),
        run_pip_audit(target, timeout=timeout),
        run_npm_audit(target, timeout=timeout),
        # Known-malicious packages (OSV MAL- records) from lockfiles; built in, no extra tool.
        run_malicious_package_check(target),
        # Maven / Gradle CVEs from OSV when Trivy isn't installed; built in, no JVM needed.
        run_java_dependency_check(target),
        # Every other lockfile (yarn, pnpm, poetry, uv, Pipfile, go.mod, pubspec.lock, Cargo.lock,
        # Gemfile.lock, packages.lock.json, composer.lock) via OSV, unless its own tool covers it.
        run_osv_dependency_check(target),
        # Typosquatted dependency names (offline) and, with --registry-check, missing or brand-new
        # packages on npm / PyPI (#142).
        run_typosquat_check(target),
    ]
    # Ecosystem-specific tools only run when their manifests exist.
    target_path = Path(target)
    if _manifest_dirs(target_path, "go.mod"):
        tasks.append(run_govulncheck(target, timeout=timeout))
    if _manifest_dirs(target_path, "composer.lock"):
        tasks.append(run_composer_audit(target, timeout=timeout))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    return collect_scan_results(results, label="SCA tool")
