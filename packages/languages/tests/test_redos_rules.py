"""Tests for catastrophic regex denial of service, excluding polynomial cases."""

from pathlib import Path

import pytest

from argus_languages.scanner import scan_path


@pytest.mark.parametrize(
    ("filename", "source"),
    [
        ("unsafe.py", 're.compile(request.args["pattern"])'),
        ("unsafe.py", 're.compile(request.args.get("pattern"))'),
        ("unsafe.py", 're.compile(request.query_params.get("pattern"))'),
        ("unsafe.py", "re.compile(req.query.pattern)"),
        ("unsafe.py", "re.compile(input())"),
        ("unsafe.js", "const pattern = new RegExp(req.query.q);"),
        ("unsafe.ts", "const pattern = new RegExp(request.body.pattern);"),
        ("unsafe.java", 'Pattern.compile(request.getParameter("re"));'),
    ],
)
def test_redos_user_controlled_patterns_flagged(tmp_path: Path, filename: str, source: str):
    f = tmp_path / filename
    f.write_text(source + "\n")
    assert "redos-user-controlled-pattern" in {
        finding.rule_id for finding in scan_path(f).findings
    }


@pytest.mark.parametrize(
    ("filename", "source"),
    [
        ("unsafe.py", 're.compile(r"(a+)+$")'),
        ("unsafe.py", 're.compile(r"A(B|C+)+D")'),
        ("unsafe.py", 're.compile(r"(a|aa)+$")'),
        ("unsafe.py", 're.compile(r"(.*a){5}$")'),
        ("unsafe.py", 're.compile(r"(\\[[^\\[\\]]*\\]|\\s+)+")'),
        ("unsafe.py", 're.compile(r"(x|x)*$")'),
        ("unsafe.js", 'const pattern = new RegExp("(a+)+$");'),
        ("unsafe.js", "const pattern = /^(a+)+$/;"),
        ("unsafe.js", "matches(value, /^(a+)+$/i);"),
        ("unsafe.js", "const config = { pattern: /^(a+)+$/ };"),
        ("unsafe.js", "return /^(a+)+$/;"),
        ("unsafe.js", "const valid = !/^(a+)+$/.test(value);"),
        ("unsafe.js", "check(value, /^(a+)+$/);"),
        ("unsafe.ts", "const pattern = /^([a-z]+)+$/i;"),
        ("unsafe.java", 'Pattern pattern = Pattern.compile("(a+)+$");'),
    ],
)
def test_redos_catastrophic_literal_patterns_flagged(
    tmp_path: Path, filename: str, source: str
):
    f = tmp_path / filename
    f.write_text(source + "\n")
    assert "redos-catastrophic-pattern" in {
        finding.rule_id for finding in scan_path(f).findings
    }


@pytest.mark.parametrize(
    ("filename", "source"),
    [
        ("safe.py", 're.compile(re.escape(request.args["pattern"]))'),
        ("safe.py", 're2.compile(request.args["pattern"])'),
        ("safe.py", 'google_re2.compile(request.args["pattern"])'),
        ("safe.py", 're.compile(r"^\\d{4}-\\d{2}-\\d{2}$")'),
        ("safe.py", 're.compile(r"(cat|dog)+$")'),
        ("safe.py", 're.compile(r"(a|\\d)+$")'),
        ("safe.py", """re.compile(r'"((?:[^"\\\\]|\\\\.)*)"')"""),
        ("safe.py", 're.compile(r"\\s*\\d{1,3}(?:\\s*,\\s*\\d{1,3})*\\s*")'),
        ("safe.py", 're.compile(r"^\"?((?:@[^@/\\s\"]+/)?[^@\\s\"]+)@")'),
        ("safe.py", 're.compile(r"(?:[\\w.-]+/)?[\\w-]+/[\\w-]+/[\\w-]+(?://.*)?")'),
        (
            "safe.py",
            're.compile(r"^#!\\s*(?:/usr)?(?:/local)?/bin/'
            '(?:env\\s+(?:-\\S+\\s+)*)?(\\w+)")',
        ),
        (
            "safe.py",
            're.compile(r"\\bchmod\\s+(?:-[a-zA-Z]+\\s+)*'
            '(?:0?[0-7]?(?:777|666)|[ugoa]*[oa][ugoa]*\\+[rxX]*w)\\b")',
        ),
        (
            "safe.py",
            r"""re.compile(r"^\s*(?:[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)*|'[^']*'|"""
            r"""\"[^\"]*\"|\d+)\s*$")""",
        ),
        ("safe.js", "const ratio = total / count; // division, not a regex"),
        ("safe.js", "// /^(a+)+$/ is documentation, not code"),
        ("safe.js", 'const pattern = new RegExp("^(cat|dog)+$");'),
        ("safe.java", 'Pattern pattern = Pattern.compile("^(cat|dog)+$");'),
        ("safe.js", "const pattern = new RegExp(escapeRegExp(req.query.q));"),
        ("safe.java", 'Pattern.compile(Pattern.quote(request.getParameter("re")));'),
    ],
)
def test_redos_safe_patterns_not_flagged(tmp_path: Path, filename: str, source: str):
    f = tmp_path / filename
    f.write_text(source + "\n")
    assert not {
        finding.rule_id
        for finding in scan_path(f).findings
        if finding.rule_id.startswith("redos-")
    }


def test_polynomial_ms_cve_pattern_is_explicitly_out_of_scope(tmp_path: Path):
    f = tmp_path / "polynomial_ms_cve.py"
    f.write_text(
        're.compile(r"^((?:\\d+)?\\.?\\d+) *(?:milliseconds?|ms)?$")\n'
    )
    rule_ids = {finding.rule_id for finding in scan_path(f).findings}
    assert "redos-catastrophic-pattern" not in rule_ids


# Scope note: polynomial ReDoS patterns such as the legacy ms/moment numeric-unit
# expression are intentionally excluded; this analyzer targets exponential
# backtracking from nested unbounded repeats and overlapping alternatives.
