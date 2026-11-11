from __future__ import annotations

from bisect import bisect_right
from pathlib import Path

from argus_languages.dependency_sources import scan_dependency_sources
from argus_languages.discover import SUPPORTED_LANGUAGES, discover_files
from argus_languages.models import Finding, ScanResult
from argus_languages.noise import IgnoreMarker, downgrade, parse_ignore, path_context
from argus_languages.rules_loader import LoadedRule, load_rules_from_dir

TOOL_NAME = "argus-languages"

COMMENT_PREFIX: dict[str, tuple[str, ...]] = {
    "javascript": ("//", "/*"),
    "typescript": ("//", "/*"),
    "vue": ("//", "/*"),
    "python": ("#",),
    "java": ("//", "/*"),
    "jsp": ("<%--", "//", "/*"),
    "kotlin": ("//", "/*"),
    "scala": ("//", "/*"),
    "php": ("//", "#", "/*", "*"),
    "blade": ("{{--",),
    "composer": (),
    "dotenv-production": ("#",),
    "dotenv-example": ("#",),
    "spring-config": ("#", "!"),
    "github-actions": ("#",),
    "go": ("//",),
    "ruby": ("#",),
    "csharp": ("//", "/*"),
    "rust": ("//",),
    "terraform": ("#", "//"),
    "ansible": ("#",),
    "docker": ("#",),
    "kubernetes": ("#",),
    "shell": ("#",),
    "batch": ("::",),
    "powershell": ("#", "<#"),
    "vbscript": ("'",),
    "hta": ("'", "//", "<!--"),
    "html": ("<!--",),
    "sql": ("--", "/*"),
    "dart": ("//",),
    "flutter": ("#", "//", "<!--"),
}


def _skip_line(line: str, language: str) -> bool:
    stripped = line.strip()
    for prefix in COMMENT_PREFIX.get(language, ("//", "#")):
        if stripped.startswith(prefix):
            return True
    return False


# Config files only get rules written for them; generic code rules would
# misfire on JSON and KEY=value lines.
CONFIG_LANGUAGES = frozenset(
    {"composer", "dotenv-production", "dotenv-example", "spring-config", "github-actions",
     "npm-manifest", "python-requirements", "python-manifest", "dependency-source"}
)


def _rule_applies(rule: LoadedRule, language: str) -> bool:
    if rule.exclude_languages and language in rule.exclude_languages:
        return False
    if rule.languages is None:
        return language not in CONFIG_LANGUAGES
    return language in rule.languages


_IGNORE_HINT = (
    " (an argus-ignore comment here was not applied: add a reason, "
    "e.g. `argus-ignore[{rule}]: why this is safe`)"
)
_MAX_SUPPRESSED_LISTED = 500


def _scan_content(
    relative: str,
    language: str,
    content: str,
    rules: list[LoadedRule],
    suppressed: list[dict[str, object]] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()
    context = path_context(relative)
    pending: IgnoreMarker | None = None  # from a comment-only line just above
    markers: list[IgnoreMarker | None] = []
    for line in lines:
        if _skip_line(line, language):
            pending = parse_ignore(line)
            markers.append(None)
            continue
        markers.append(parse_ignore(line) or pending)
        pending = None

    for rule in rules:
        if not _rule_applies(rule, language):
            continue

        if rule.multiline:
            source = "\n".join("" if _skip_line(line, language) else line for line in lines)
            line_starts = [0]
            line_starts.extend(
                index + 1 for index, character in enumerate(source) if character == "\n"
            )
            matching_lines = {
                bisect_right(line_starts, match.start())
                for match in rule.pattern.finditer(source)
            }
        else:
            matching_lines = {
                i
                for i, line in enumerate(lines, start=1)
                if not _skip_line(line, language) and rule.pattern.search(line)
            }

        for i in sorted(matching_lines):
            marker = markers[i - 1]
            description = f"Language: {language}"
            if marker is not None and rule.allow_inline_ignore and marker.covers(rule.id):
                if marker.reason:
                    if suppressed is not None:
                        suppressed.append(
                            {
                                "rule_id": rule.id,
                                "file": relative,
                                "line": i,
                                "reason": marker.reason,
                            }
                        )
                    continue
                description += _IGNORE_HINT.format(rule=rule.id)

            severity = rule.severity
            finding_context = ""
            if context and rule.context_sensitive:
                severity = downgrade(severity)
                finding_context = context
            findings.append(
                Finding(
                    title=rule.title,
                    severity=severity,
                    tool=TOOL_NAME,
                    file=relative,
                    line=i,
                    rule_id=rule.id,
                    description=description,
                    language=language,
                    data_classification=rule.data_classification,
                    fix_guidance=rule.fix_guidance,
                    confidence=rule.confidence,
                    context=finding_context,
                )
            )
    return findings


def scan_path(target: str | Path, rules: list[LoadedRule] | None = None) -> ScanResult:
    path = Path(target).resolve()
    result = ScanResult(tool=TOOL_NAME, target=str(path))
    if not path.exists():
        result.errors.append(f"Target not found: {path}")
        return result

    loaded = rules if rules is not None else load_rules_from_dir()
    files = discover_files(path)
    if not files:
        result.errors.append(
            f"No scannable files found. Supported: {', '.join(SUPPORTED_LANGUAGES)}"
        )
        return result

    lang_counts: dict[str, int] = {}
    suppressed: list[dict[str, object]] = []
    for scanned in files:
        lang_counts[scanned.language] = lang_counts.get(scanned.language, 0) + 1
        try:
            content = scanned.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        result.findings.extend(
            _scan_content(scanned.relative, scanned.language, content, loaded, suppressed)
        )
        dependency_findings = scan_dependency_sources(
            scanned.relative, scanned.language, content, loaded
        )
        for finding in dependency_findings:
            if finding.rule_id == "dependency-http-source" and any(
                f.file == finding.file and f.line == finding.line
                and f.rule_id == "composer-insecure-repository" for f in result.findings
            ):
                continue
            result.findings.append(finding)

    result.metadata["files_scanned"] = len(files)
    if suppressed:
        result.metadata["suppressed_count"] = len(suppressed)
        result.metadata["suppressed"] = suppressed[:_MAX_SUPPRESSED_LISTED]
    result.metadata["languages"] = lang_counts
    return result


def scan_directory(target: str | Path) -> ScanResult:
    """Scan a directory or file for security patterns across all supported languages."""
    return scan_path(target)
