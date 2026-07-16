from __future__ import annotations

from pathlib import Path

from argus_languages.discover import SUPPORTED_LANGUAGES, discover_files
from argus_languages.models import Finding, ScanResult, Severity
from argus_languages.rules_loader import LoadedRule, load_rules_from_dir

TOOL_NAME = "argus-languages"

COMMENT_PREFIX: dict[str, tuple[str, ...]] = {
    "javascript": ("//", "/*"),
    "typescript": ("//", "/*"),
    "vue": ("//", "/*"),
    "python": ("#",),
    "java": ("//", "/*"),
    "kotlin": ("//", "/*"),
    "scala": ("//", "/*"),
    "php": ("//", "#", "/*"),
    "go": ("//",),
    "ruby": ("#",),
    "csharp": ("//", "/*"),
    "rust": ("//",),
    "terraform": ("#", "//"),
    "ansible": ("#",),
    "docker": ("#",),
    "kubernetes": ("#",),
    "shell": ("#",),
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


def _rule_applies(rule: LoadedRule, language: str) -> bool:
    if rule.languages is None:
        return True
    return language in rule.languages


def _scan_content(
    relative: str,
    language: str,
    content: str,
    rules: list[LoadedRule],
) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(content.splitlines(), start=1):
        if _skip_line(line, language):
            continue
        for rule in rules:
            if not _rule_applies(rule, language):
                continue
            if rule.pattern.search(line):
                findings.append(
                    Finding(
                        title=rule.title,
                        severity=rule.severity,
                        tool=TOOL_NAME,
                        file=relative,
                        line=i,
                        rule_id=rule.id,
                        description=f"Language: {language}",
                        language=language,
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
    for scanned in files:
        lang_counts[scanned.language] = lang_counts.get(scanned.language, 0) + 1
        try:
            content = scanned.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        result.findings.extend(_scan_content(scanned.relative, scanned.language, content, loaded))

    result.metadata["files_scanned"] = len(files)
    result.metadata["languages"] = lang_counts
    return result


def scan_directory(target: str | Path) -> ScanResult:
    """Scan a directory or file for security patterns across all supported languages."""
    return scan_path(target)
