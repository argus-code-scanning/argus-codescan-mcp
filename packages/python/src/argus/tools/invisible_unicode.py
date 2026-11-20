"""Invisible Unicode and Trojan Source check for the malware scan.

Text that an editor or a diff does not show but a compiler, interpreter or model
still reads: bidi controls (Trojan Source, CVE-2021-42574), zero-width characters,
variation selectors and tag characters (GlassWorm, ASCII smuggling) and long runs
of private-use characters.

This is a Python check rather than YAML rules: the YAML scanner skips comment
lines, which is where Trojan Source usually hides, and the exceptions (a BOM at
the start of a file, ZWJ and variation selectors inside emoji, a flag's tag
sequence) need to look at the characters around a match.

AI agent rules files (CLAUDE.md, AGENTS.md, .cursorrules, ...) are left to the
`agent-rules-invisible-unicode` rule, so a character there is reported once.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from pathlib import Path

from argus_languages.discover import SKIP_DIRS, discover_files

from argus.models import Finding, ScanType, Severity

TOOL = "argus-malware"
MARKDOWN_SUFFIXES = (".md", ".mdx", ".markdown")
AGENT_RULES_LANGUAGE = "agent-rules"
PRIVATE_USE_RUN = 10

BIDI = frozenset(range(0x202A, 0x202F)) | frozenset(range(0x2066, 0x206A))
ZERO_WIDTH = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF})
ZWJ = 0x200D
ZWNJ = 0x200C
# Scripts whose spelling uses ZWNJ/ZWJ between letters (Persian, Hindi, Kannada, Odia, ...):
# Arabic and its extensions, the Brahmic blocks from Devanagari to Sinhala, Tibetan, Myanmar,
# Khmer and Mongolian.
JOINER_SCRIPTS = (
    (0x0600, 0x06FF),
    (0x0750, 0x077F),
    (0x08A0, 0x08FF),
    (0x0900, 0x0DFF),
    (0x0F00, 0x0FFF),
    (0x1000, 0x109F),
    (0x1780, 0x17FF),
    (0x1800, 0x18AF),
    (0xFB50, 0xFDFF),
    (0xFE70, 0xFEFE),
)
EMOJI_PRESENTATION = frozenset({0xFE0E, 0xFE0F})
BLACK_FLAG = 0x1F3F4
CANCEL_TAG = 0xE007F


def _is_variation_selector(cp: int) -> bool:
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


def _is_tag(cp: int) -> bool:
    return 0xE0000 <= cp <= 0xE007F


def _is_private_use(cp: int) -> bool:
    return 0xE000 <= cp <= 0xF8FF


def _is_emoji(cp: int) -> bool:
    """A character that can start or continue an emoji sequence (approximate)."""
    return (
        0x1F000 <= cp <= 0x1FAFF
        or 0x2190 <= cp <= 0x2BFF
        or cp in (0x00A9, 0x00AE, 0x203C, 0x2049, 0x2122, 0x2139, 0x20E3, 0x3030, 0x303D)
        or cp in EMOJI_PRESENTATION
    )


def _after_joiner_script(line: str, index: int) -> bool:
    """Whether the character before `index` belongs to a script that spells with ZWNJ/ZWJ."""
    if index == 0:
        return False
    prev = ord(line[index - 1])
    return any(low <= prev <= high for low, high in JOINER_SCRIPTS)


def _name(cp: int) -> str:
    if _is_private_use(cp):
        return "PRIVATE USE CHARACTER"
    return unicodedata.name(chr(cp), "UNNAMED CHARACTER")


def _describe(cp: int, column: int) -> str:
    return f"U+{cp:04X} {_name(cp)} at col {column}"


@dataclass(frozen=True)
class _Class:
    rule_id: str
    title: str
    code_severity: Severity
    markdown_severity: Severity
    why: str


BIDI_CLASS = _Class(
    "malware-unicode-bidi-control",
    "Bidirectional control character (Trojan Source)",
    Severity.HIGH,
    Severity.HIGH,
    "Bidi controls make text display in a different order from how it is stored and "
    "compiled, so a reviewer reads different code from what runs (CVE-2021-42574).",
)
ZERO_WIDTH_CLASS = _Class(
    "malware-unicode-zero-width",
    "Zero-width character",
    Severity.MEDIUM,
    Severity.MEDIUM,
    "Zero-width characters are invisible in editors and diffs; they can split a "
    "keyword or an identifier so that two names that look the same are different.",
)
HIDDEN_SELECTOR_CLASS = _Class(
    "malware-unicode-hidden-selector",
    "Variation selector or tag character outside an emoji",
    Severity.HIGH,
    Severity.MEDIUM,
    "Variation selectors and tag characters render as nothing; GlassWorm hid its "
    "loader in them and ASCII smuggling hides prompt-injection text in tag characters.",
)
PRIVATE_USE_CLASS = _Class(
    "malware-unicode-private-use-run",
    f"Run of {PRIVATE_USE_RUN} or more private-use characters",
    Severity.HIGH,
    Severity.HIGH,
    "Long runs of private-use characters have no visible meaning in source code and "
    "were used to carry an encoded payload (GlassWorm).",
)

FIX = (
    "Show the file with invisible characters made visible (for example `cat -A`, or an "
    "editor's 'render control characters' setting) and remove every character that is "
    "not meant to be there. If the file arrived in a pull request or a dependency, treat "
    "it as hostile until you know why the characters are there."
)


def _emoji_neighbour(line: str, index: int, step: int) -> bool:
    """Whether the next character in `step` direction (skipping skin-tone modifiers and
    presentation selectors) is part of an emoji."""
    i = index + step
    while 0 <= i < len(line):
        cp = ord(line[i])
        if 0x1F3FB <= cp <= 0x1F3FF or cp in EMOJI_PRESENTATION:
            i += step
            continue
        return _is_emoji(cp)
    return False


def _flag_tag_run(line: str, start: int, end: int) -> bool:
    """A tag run that spells a subdivision flag: U+1F3F4 BLACK FLAG + tag letters + CANCEL TAG."""
    return start > 0 and ord(line[start - 1]) == BLACK_FLAG and ord(line[end - 1]) == CANCEL_TAG


def _scan_line(line: str, file_start: bool) -> dict[_Class, tuple[int, list[str]]]:
    """Per class: the first column it was found at, and each character (or run) found."""
    hits: dict[_Class, tuple[int, list[str]]] = {}

    def hit(cls: _Class, column: int, text: str) -> None:
        hits.setdefault(cls, (column, []))[1].append(text)

    i = 0
    while i < len(line):
        cp = ord(line[i])
        column = i + 1
        if cp in BIDI:
            hit(BIDI_CLASS, column, _describe(cp, column))
        elif cp in ZERO_WIDTH:
            if cp == 0xFEFF and file_start and i == 0:
                pass  # byte order mark
            elif cp == ZWJ and _emoji_neighbour(line, i, -1) and _emoji_neighbour(line, i, 1):
                pass  # inside an emoji sequence such as woman + ZWJ + laptop
            elif cp in (ZWNJ, ZWJ) and _after_joiner_script(line, i):
                pass  # ordinary spelling in Persian, Hindi, Kannada, ...
            else:
                hit(ZERO_WIDTH_CLASS, column, _describe(cp, column))
        elif _is_tag(cp):
            end = i
            while end < len(line) and _is_tag(ord(line[end])):
                end += 1
            if not _flag_tag_run(line, i, end):
                hidden = "".join(
                    chr(ord(c) - 0xE0000) for c in line[i:end] if 0x20 <= ord(c) - 0xE0000 < 0x7F
                )
                text = f"{end - i} tag character(s) from col {column}"
                if hidden:
                    text += f", hidden text {hidden[:80]!r}"
                hit(HIDDEN_SELECTOR_CLASS, column, text)
            i = end
            continue
        elif _is_variation_selector(cp):
            # U+FE0E/U+FE0F after an emoji or a keycap base (a red heart, keycap 1) choose how it is drawn
            prev = line[i - 1] if i > 0 else ""
            in_emoji = (
                cp in EMOJI_PRESENTATION
                and prev
                and (_is_emoji(ord(prev)) or prev in "0123456789#*")
            )
            if not in_emoji:
                hit(HIDDEN_SELECTOR_CLASS, column, _describe(cp, column))
        elif _is_private_use(cp):
            end = i
            while end < len(line) and _is_private_use(ord(line[end])):
                end += 1
            if end - i >= PRIVATE_USE_RUN:
                hit(
                    PRIVATE_USE_CLASS,
                    column,
                    f"{end - i} private-use characters (U+{cp:04X}...) from col {column}",
                )
            i = end
            continue
        i += 1
    return hits


def scan_text(text: str, relative: str, markdown: bool = False) -> list[Finding]:
    """Findings for one file's text: one per line and class, naming each character and column."""
    findings: list[Finding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for cls, (first_column, details) in _scan_line(line, file_start=line_no == 1).items():
            findings.append(
                Finding(
                    title=cls.title,
                    severity=cls.markdown_severity if markdown else cls.code_severity,
                    scan_type=ScanType.MALWARE,
                    tool=TOOL,
                    file=relative,
                    line=line_no,
                    column=first_column,
                    description=f"{'; '.join(details)}. {cls.why}",
                    rule_id=cls.rule_id,
                    cwe="CWE-1007",
                    fix_guidance=FIX,
                    references=["https://trojansource.codes/"],
                )
            )
    return findings


def _markdown_files(root: Path) -> list[Path]:
    out: list[Path] = []

    def walk(directory: Path, depth: int) -> None:
        if depth > 16:
            return
        try:
            entries = list(directory.iterdir())
        except OSError:
            return
        for entry in entries:
            if entry.is_symlink() or entry.name in SKIP_DIRS or entry.name.startswith("."):
                continue
            if entry.is_dir():
                walk(entry, depth + 1)
            elif entry.suffix.lower() in MARKDOWN_SUFFIXES:
                out.append(entry)

    walk(root, 0)
    return out


def scan_invisible_unicode(target: str | Path) -> list[Finding]:
    """Invisible-character findings for every source file the language scanner reads, and Markdown."""
    path = Path(target).resolve()
    if not path.exists():
        return []
    root = path if path.is_dir() else path.parent
    discovered = discover_files(path)
    files = [(f.path, f.relative, False) for f in discovered]
    if path.is_dir():
        files += [(p, str(p.relative_to(root)), True) for p in _markdown_files(path)]
    elif path.suffix.lower() in MARKDOWN_SUFFIXES:
        files.append((path, path.name, True))

    findings: list[Finding] = []
    seen = {f.path.resolve() for f in discovered if f.language == AGENT_RULES_LANGUAGE}
    for file_path, relative, markdown in files:
        resolved = file_path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(scan_text(text, relative, markdown=markdown))
    return findings
