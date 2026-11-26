from __future__ import annotations

import ast
import re
from bisect import bisect_right
from pathlib import Path

from argus_languages.dependency_sources import scan_dependency_sources
from argus_languages.discover import SUPPORTED_LANGUAGES, discover_files
from argus_languages.models import Finding, ScanResult, Severity
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
    "agent-rules": (),  # Markdown: "#" starts a heading, not a comment
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


def _python_inert_string_lines(content: str) -> set[int]:
    """Lines of Python string literals that are statements on their own (docstrings and
    string "comments"). They never run, so they are documentation, not code."""
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return set()
    lines: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            lines.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    return lines


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
     "npm-manifest", "python-requirements", "python-manifest", "dependency-source", "agent-rules"}
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
    include_regex_analysis: bool = True,
) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()
    context = path_context(relative)
    pending: IgnoreMarker | None = None  # from a comment-only line just above
    # Python docstrings are documentation. Malware rules (allow_inline_ignore=False) still
    # read them: a payload can sit in a docstring and run via exec(__doc__).
    docstrings = _python_inert_string_lines(content) if language == "python" else set()
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

        skip_docs = docstrings if rule.allow_inline_ignore else set()
        if rule.multiline:
            source = "\n".join(
                "" if _skip_line(line, language) or n in skip_docs else line
                for n, line in enumerate(lines, start=1)
            )
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
                if not _skip_line(line, language)
                and i not in skip_docs
                and rule.pattern.search(line)
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
    if include_regex_analysis:
        regex_findings = _regex_dos_findings(relative, language, content)
    else:
        regex_findings = []
    for finding in regex_findings:
        marker = markers[finding.line - 1]
        if marker is not None and marker.covers(finding.rule_id):
            if marker.reason:
                if suppressed is not None:
                    suppressed.append(
                        {
                            "rule_id": finding.rule_id,
                            "file": relative,
                            "line": finding.line,
                            "reason": marker.reason,
                        }
                    )
                continue
            finding.description += _IGNORE_HINT.format(rule=finding.rule_id)
        if context:
            finding.severity = downgrade(finding.severity)
            finding.context = context
        findings.append(finding)
    return findings



def _regex_pattern_is_dangerous(pattern: str) -> bool:
    if not pattern or len(pattern) > 2048:
        return False
    try:
        try:
            from re import _parser as parser
        except ImportError:  # Python 3.10
            import sre_parse as parser
        parsed = parser.parse(pattern)
    except (re.error, ValueError, RecursionError, OverflowError):
        return False

    repeat_ops = {
        parser.MAX_REPEAT,
        parser.MIN_REPEAT,
        getattr(parser, "POSSESSIVE_REPEAT", object()),
    }
    unbounded = parser.MAXREPEAT

    def category_characters(category):
        if category == parser.CATEGORY_DIGIT:
            return set("0123456789")
        if category == parser.CATEGORY_SPACE:
            return set(" \\t\\n\\r\\f\\v")
        if category == parser.CATEGORY_WORD:
            return set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
        if category == parser.CATEGORY_NOT_SPACE:
            return {chr(value) for value in range(128) if not chr(value).isspace()}
        return None

    def first_chars(tokens):
        chars = set()
        wildcard = False
        for op, arg in tokens:
            if op == parser.LITERAL:
                chars.add(chr(arg))
                return chars, wildcard
            if op == parser.IN:
                negated = any(item_op == parser.NEGATE for item_op, _ in arg)
                excluded = set()
                for item_op, item_arg in arg:
                    if item_op == parser.LITERAL:
                        (excluded if negated else chars).add(chr(item_arg))
                    elif item_op == parser.RANGE:
                        start, end = item_arg
                        target = excluded if negated else chars
                        if end - start <= 256:
                            target.update(chr(value) for value in range(start, end + 1))
                        else:
                            wildcard = True
                    elif item_op == parser.CATEGORY:
                        category = category_characters(item_arg)
                        if category is None:
                            wildcard = True
                        else:
                            (excluded if negated else chars).update(category)
                    elif item_op != parser.NEGATE:
                        wildcard = True
                if negated and not wildcard:
                    chars.update(chr(value) for value in range(128) if chr(value) not in excluded)
                return chars, wildcard
            if op == parser.CATEGORY:
                category = category_characters(arg)
                if category is None:
                    return chars, True
                return category, False
            if op == parser.ANY:
                return chars, True
            if op == parser.SUBPATTERN:
                return first_chars(arg[-1])
            if op == parser.BRANCH:
                for branch in arg[1]:
                    branch_chars, branch_wildcard = first_chars(branch)
                    chars.update(branch_chars)
                    wildcard = wildcard or branch_wildcard
                return chars, wildcard
            if op in repeat_ops:
                branch_chars, branch_wildcard = first_chars(arg[2])
                chars.update(branch_chars)
                wildcard = wildcard or branch_wildcard
                return chars, wildcard
            if op in {parser.AT, getattr(parser, "ASSERT", object()),
                      getattr(parser, "ASSERT_NOT", object())}:
                continue
            return chars, True
        return chars, wildcard

    def has_overlapping_alternatives(tokens):
        for op, arg in tokens:
            if op == parser.BRANCH:
                branches = arg[1]
                if any(not branch for branch in branches):
                    return True
                first_sets = [first_chars(branch) for branch in branches]
                for index, (left_chars, left_wildcard) in enumerate(first_sets):
                    for right_chars, right_wildcard in first_sets[index + 1:]:
                        if (
                            left_wildcard
                            or right_wildcard
                            or left_chars.intersection(right_chars)
                        ):
                            return True
                if any(has_overlapping_alternatives(branch) for branch in branches):
                    return True
            elif op == parser.SUBPATTERN and has_overlapping_alternatives(arg[-1]):
                return True
            elif op in repeat_ops and has_overlapping_alternatives(arg[2]):
                return True
        return False

    def contains_unbounded_repeat(tokens):
        for op, arg in tokens:
            if op in repeat_ops:
                if arg[1] == unbounded or contains_unbounded_repeat(arg[2]):
                    return True
            elif op == parser.SUBPATTERN and contains_unbounded_repeat(arg[-1]):
                return True
            elif op == parser.BRANCH and any(
                contains_unbounded_repeat(branch) for branch in arg[1]
            ):
                return True
        return False

    def nullable(op, arg):
        if op in {parser.AT, getattr(parser, "ASSERT", object()),
                  getattr(parser, "ASSERT_NOT", object())}:
            return True
        if op in repeat_ops:
            return arg[0] == 0 or nullable_sequence(arg[2])
        if op == parser.SUBPATTERN:
            return nullable_sequence(arg[-1])
        if op == parser.BRANCH:
            return any(nullable_sequence(branch) for branch in arg[1])
        return False

    def nullable_sequence(tokens):
        return all(nullable(op, arg) for op, arg in tokens)

    def has_required_non_overlapping_delimiter(tokens, repeat_index):
        repeat_chars, repeat_wildcard = first_chars(tokens[repeat_index][1][2])
        if repeat_wildcard:
            return False

        def is_disjoint_delimiter(op, arg):
            if op == parser.LITERAL:
                delimiter_chars = {chr(arg)}
                delimiter_wildcard = False
            elif op == parser.CATEGORY:
                delimiter_chars = category_characters(arg)
                delimiter_wildcard = delimiter_chars is None
            elif op == parser.IN:
                delimiter_chars, delimiter_wildcard = first_chars([(op, arg)])
            elif op in repeat_ops and arg[0] > 0:
                delimiter_chars, delimiter_wildcard = first_chars(arg[2])
            else:
                return False
            return (
                not delimiter_wildcard
                and delimiter_chars is not None
                and not repeat_chars.intersection(delimiter_chars)
            )

        return any(
            is_disjoint_delimiter(op, arg) for op, arg in tokens[:repeat_index]
        ) or any(
            is_disjoint_delimiter(op, arg) for op, arg in tokens[repeat_index + 1:]
        )

    def has_nested_repeat_without_required_separator(tokens):
        for index, (op, arg) in enumerate(tokens):
            if op in repeat_ops:
                nested = arg[1] == unbounded or has_nested_repeat_without_required_separator(
                    arg[2]
                )
                if (
                    nested
                    and not has_required_non_overlapping_delimiter(tokens, index)
                    and all(
                        nullable(next_op, next_arg)
                        for next_op, next_arg in tokens[index + 1:]
                    )
                ):
                    return True
            elif op == parser.SUBPATTERN:
                nested = has_nested_repeat_without_required_separator(arg[-1])
                if nested and all(
                    nullable(next_op, next_arg) for next_op, next_arg in tokens[index + 1:]
                ):
                    return True
            elif op == parser.BRANCH:
                nested = any(
                    has_nested_repeat_without_required_separator(branch) for branch in arg[1]
                )
                if nested and all(
                    nullable(next_op, next_arg) for next_op, next_arg in tokens[index + 1:]
                ):
                    return True
        return False

    def has_ambiguous_adjacent_repeats(tokens):
        for index, (op, arg) in enumerate(tokens):
            if (
                op not in repeat_ops
                or arg[1] != unbounded
                or not contains_unbounded_repeat(arg[2])
            ):
                continue
            # Adjacent bounded or optional quantifiers can be polynomial; this
            # check is limited to unbounded outer repetitions.
            left_chars, left_wildcard = first_chars(arg[2])
            for next_op, next_arg in tokens[index + 1:]:
                if nullable(next_op, next_arg):
                    continue
                if next_op not in repeat_ops:
                    break
                right_chars, right_wildcard = first_chars(next_arg[2])
                if (
                    left_wildcard
                    or right_wildcard
                    or left_chars.intersection(right_chars)
                ):
                    return True
                break
        return False

    def inspect(tokens):
        if has_ambiguous_adjacent_repeats(tokens):
            return True
        for op, arg in tokens:
            if op in repeat_ops:
                maximum, child = arg[1], arg[2]
                if maximum == unbounded and has_overlapping_alternatives(child):
                    return True
                if (
                    maximum == unbounded
                    and has_nested_repeat_without_required_separator(child)
                ):
                    return True
                if maximum > 1 and maximum != unbounded and contains_unbounded_repeat(child):
                    return True
                if inspect(child):
                    return True
            elif op == parser.SUBPATTERN and inspect(arg[-1]):
                return True
            elif op == parser.BRANCH and any(inspect(branch) for branch in arg[1]):
                return True
        return False

    try:
        return inspect(parsed)
    except RecursionError:
        return False


def _regex_dos_findings(relative: str, language: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()

    if language == "python":
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            tree = None
        if tree is not None:
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                owner = node.func.value
                method = node.func.attr
                if not isinstance(owner, ast.Name) or owner.id not in {"re", "regex"}:
                    continue
                if method not in {"compile", "search", "match", "fullmatch", "findall", "finditer"}:
                    continue
                argument = node.args[0] if node.args else next(
                    (kw.value for kw in node.keywords if kw.arg in {"pattern", "regex"}), None
                )
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    if _regex_pattern_is_dangerous(argument.value):
                        findings.append(
                            Finding(
                                title="Potential catastrophic regular expression",
                                severity=Severity.HIGH,
                                tool=TOOL_NAME,
                                file=relative,
                                line=node.lineno,
                                rule_id="redos-catastrophic-pattern",
                                description=f"Language: {language}",
                                language=language,
                                confidence="high",
                                fix_guidance=(
                                    "Avoid nested unbounded quantifiers and "
                                    "overlapping alternatives. Rewrite the expression "
                                    "for predictable matching time or use RE2."
                                ),
                            )
                        )
                elif argument is not None:
                    escaped = (
                        isinstance(argument, ast.Call)
                        and isinstance(argument.func, ast.Attribute)
                        and isinstance(argument.func.value, ast.Name)
                        and argument.func.value.id == "re"
                        and argument.func.attr == "escape"
                    )
                    if escaped:
                        continue
                    if _is_request_pattern(argument):
                        findings.append(
                            Finding(
                                title="Regular expression compiled from user-controlled input",
                                severity=Severity.HIGH,
                                tool=TOOL_NAME,
                                file=relative,
                                line=node.lineno,
                                rule_id="redos-user-controlled-pattern",
                                description=f"Language: {language}",
                                language=language,
                                confidence="high",
                                fix_guidance=(
                                    "Escape user input with re.escape before compiling it, "
                                    "or use an RE2-compatible engine for untrusted patterns."
                                ),
                            )
                        )

    if language in {"javascript", "typescript", "java"}:
        for line_number, line in enumerate(lines, start=1):
            if _skip_line(line, language):
                continue
            literal_patterns = _literal_regex_patterns(line, language)
            if language in {"javascript", "typescript"}:
                literal_patterns.extend(_javascript_regex_literals(line))
            for literal in literal_patterns:
                if _regex_pattern_is_dangerous(literal):
                    findings.append(
                        Finding(
                            title="Potential catastrophic regular expression",
                            severity=Severity.HIGH,
                            tool=TOOL_NAME,
                            file=relative,
                            line=line_number,
                            rule_id="redos-catastrophic-pattern",
                            description=f"Language: {language}",
                            language=language,
                            confidence="high",
                            fix_guidance=(
                                "Avoid nested unbounded quantifiers and overlapping alternatives. "
                                "Rewrite the expression for predictable matching time or use RE2."
                            ),
                        )
                    )

    if language in {"javascript", "typescript"}:
        dynamic_pattern = re.compile(
            r"\bnew\s+RegExp\s*\(\s*(?!escapeRegExp\s*\()"
            r"(?:(?:req|request)\s*\.\s*(?:query|body|params)\b|"
            r"(?:req|request)\s*\[\s*['\"](?:query|body|params)['\"])",
            re.IGNORECASE,
        )
    elif language == "java":
        dynamic_pattern = re.compile(
            r"\bPattern\.compile\s*\(\s*(?!Pattern\.quote\s*\()"
            r"request\.getParameter\s*\(",
            re.IGNORECASE,
        )
    else:
        dynamic_pattern = None

    if dynamic_pattern is not None:
        for line_number, line in enumerate(lines, start=1):
            if _skip_line(line, language) or not dynamic_pattern.search(line):
                continue
            findings.append(
                Finding(
                    title="Regular expression compiled from user-controlled input",
                    severity=Severity.HIGH,
                    tool=TOOL_NAME,
                    file=relative,
                    line=line_number,
                    rule_id="redos-user-controlled-pattern",
                    description=f"Language: {language}",
                    language=language,
                    confidence="high",
                    fix_guidance=(
                        "Escape user input before constructing a regular expression, "
                        "or use an RE2-compatible engine for untrusted patterns."
                    ),
                )
            )

    return findings



def _literal_regex_patterns(line: str, language: str) -> list[str]:
    if language in {"javascript", "typescript"}:
        calls = re.compile(r"\bnew\s+RegExp\s*\(")
    elif language == "java":
        calls = re.compile(r"\bPattern\.compile\s*\(")
    else:
        return []

    patterns = []
    for match in calls.finditer(line):
        position = match.end()
        while position < len(line) and line[position].isspace():
            position += 1
        if position >= len(line) or line[position] not in {"'", '"'}:
            continue
        quote = line[position]
        end = position + 1
        escaped = False
        while end < len(line):
            character = line[end]
            if character == quote and not escaped:
                break
            if character == "\\" and not escaped:
                escaped = True
            else:
                escaped = False
            end += 1
        if end >= len(line):
            continue
        try:
            value = ast.literal_eval(line[position:end + 1])
        except (SyntaxError, ValueError):
            continue
        if isinstance(value, str):
            patterns.append(value)
    return patterns

def _javascript_regex_literals(line: str) -> list[str]:
    """Extract regex literals in expression positions.

    Avoid treating division operators and line comments as regex literals.
    """
    prefix = re.compile(r"(?:^|[=(,:!]\s*|\breturn\s+)/")
    patterns: list[str] = []
    for match in prefix.finditer(line):
        start = match.end() - 1
        if line.startswith("//", start) or line.startswith("/=", start):
            continue
        escaped = False
        in_class = False
        end = start + 1
        while end < len(line):
            character = line[end]
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == "[":
                in_class = True
            elif character == "]":
                in_class = False
            elif character == "/" and not in_class:
                break
            end += 1
        if end >= len(line) or line[end] != "/":
            continue
        flags_end = end + 1
        while flags_end < len(line) and line[flags_end].isalpha():
            flags_end += 1
        if flags_end < len(line) and (line[flags_end].isalnum() or line[flags_end] in "_$"):
            continue
        patterns.append(line[start + 1:end])
    return patterns


def _is_request_pattern(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "input":
            return True
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr.lower() in {"get", "getlist", "json"}
            and _is_request_pattern(node.func.value)
        )
    if isinstance(node, ast.Attribute):
        if node.attr.lower() in {
            "query", "body", "params", "args", "form", "get", "post",
            "json", "data", "values", "query_params",
        }:
            return isinstance(node.value, ast.Name) and node.value.id in {"request", "req"}
        return _is_request_pattern(node.value)
    if isinstance(node, ast.Subscript):
        return (
            isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id in {"request", "req"}
            and node.value.attr.lower() in {
                "args", "query", "form", "get", "post", "json", "data", "values",
                "query_params",
            }
        )
    return False

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
            _scan_content(
                scanned.relative,
                scanned.language,
                content,
                loaded,
                suppressed,
                include_regex_analysis=rules is None,
            )
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
