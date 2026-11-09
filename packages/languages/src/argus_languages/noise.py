"""False-positive controls: path context, severity downgrade and inline ignore comments."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from argus_languages.models import Severity

# Directory names whose code normally does not ship.
_TEST_DIRS = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "__mocks__",
        "spec",
        "specs",
        "fixtures",
        "fixture",
        "testdata",
        "test-data",
        "test_data",
        "e2e",
        "cypress",
    }
)
_DOCS_DIRS = frozenset({"docs", "doc", "examples", "example", "samples", "sample", "demo", "demos"})

_TEST_FILE_RE = re.compile(
    r"(^test_.+\.py$|_test\.(py|go)$|\.(test|spec)\.[cm]?[jt]sx?$|"
    r"(Test|Tests|IT)\.(java|kt|cs)$|_spec\.rb$|Test\.php$)"
)
_GENERATED_FILE_RE = re.compile(r"\.(min|bundle|chunk)\.[cm]?js$")


def path_context(relative: str) -> str:
    """Return "test", "docs", "generated" or "" for a scan-root-relative POSIX path."""
    path = PurePosixPath(relative)
    name = path.name
    dirs = {part.lower() for part in path.parts[:-1]}
    if dirs & _TEST_DIRS or _TEST_FILE_RE.search(name):
        return "test"
    if _GENERATED_FILE_RE.search(name):
        return "generated"
    if dirs & _DOCS_DIRS:
        return "docs"
    return ""


_DOWNGRADE = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.MODERATE: Severity.LOW,
    Severity.LOW: Severity.INFO,
    Severity.INFO: Severity.INFO,
}


def downgrade(severity: Severity) -> Severity:
    return _DOWNGRADE.get(severity, severity)


# argus-ignore[rule-a, rule-b]: reason     (only those rules)
# argus-ignore: reason                     (every rule on the line)
_IGNORE_RE = re.compile(r"argus-ignore(?:\[(?P<rules>[^\]]*)\])?(?P<rest>.*)$")
_COMMENT_CLOSERS = ("*/", "-->", "--}}", "%>", "#>")


@dataclass(frozen=True)
class IgnoreMarker:
    rules: frozenset[str] | None  # None means every rule
    reason: str

    def covers(self, rule_id: str) -> bool:
        return self.rules is None or rule_id in self.rules


def parse_ignore(line: str) -> IgnoreMarker | None:
    """Parse an `argus-ignore` comment on this line, if any."""
    if "argus-ignore" not in line:
        return None
    match = _IGNORE_RE.search(line)
    if match is None:
        return None
    rules = None
    if match.group("rules") is not None:
        names = {r.strip() for r in match.group("rules").split(",") if r.strip()}
        rules = frozenset(names) if names else None
    rest = match.group("rest").strip()
    reason = ""
    if rest.startswith(":"):
        reason = rest[1:].strip()
        for closer in _COMMENT_CLOSERS:
            if reason.endswith(closer):
                reason = reason[: -len(closer)].rstrip()
    return IgnoreMarker(rules=rules, reason=reason)
