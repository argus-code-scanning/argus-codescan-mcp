"""Is the app tested? Checks for `argus scan vibe` (#276).

Apps built mostly with AI tools often ship with no tests, a placeholder `npm test`, or tests
that assert nothing. These checks read the repo (nothing is run) and report:

- no test runner, or no tests at all
- the placeholder ``"test": "echo \\"Error: no test specified\\" && exit 1"`` script
- routes, server actions and Python endpoints that change data with no test that mentions them
- test files with no assertions; focused (``.only``) or skipped tests left in
- tests that CI never runs
- no end-to-end test although the app has login, signup or checkout pages

Each finding's fix says what to test and with which runner, so `argus scan vibe` can turn it
into a prompt that writes the tests.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from argus.models import Finding, ScanResult, ScanType, Severity
from argus.tools.vibe_checks import (
    _DATA_CHANGE,
    _PY_DATA_CHANGE,
    _PY_MUTATION_ROUTE,
    _ROUTE_MUTATION,
    _SERVER_ACTION,
    _USE_SERVER,
    Project,
    _line_of,
    _read,
    _rel,
    discover,
)

TOOL = "argus-tests"
_SOURCE_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".py"}
_TEST_FILE = re.compile(
    r"(?:\.(?:test|spec|e2e|cy)\.[cm]?[jt]sx?$|^test_.*\.py$|_test\.py$|^conftest\.py$)"
)
_TEST_DIRS = {"__tests__", "tests", "test", "e2e", "cypress", "playwright", "spec"}
_JS_RUNNERS = (
    ("vitest", "vitest"),
    ("jest", "jest"),
    ("@playwright/test", "Playwright"),
    ("cypress", "Cypress"),
    ("mocha", "mocha"),
    ("ava", "ava"),
    ("uvu", "uvu"),
    ("@testing-library/", "Testing Library"),
)
_E2E_DEPS = ("@playwright/test", "playwright", "cypress", "puppeteer", "@wdio/")
_PLACEHOLDER_TEST = re.compile(r"no test specified", re.I)
_ASSERTION = re.compile(
    r"\bexpect\s*\(|\bassert\b|\.should\b|\bt\.(?:is|true|false|deepEqual|equal|throws)\b"
    r"|\bpytest\.raises\b|\bself\.assert\w*\(|\.toBe\w*\(|\.toEqual\(|\.toMatch\w*\(",
)
_JS_TEST_CASE = re.compile(r"\b(?:it|test)\s*\(")
_PY_TEST_CASE = re.compile(r"^\s*(?:async\s+)?def\s+test_\w*\s*\(", re.M)
_FOCUSED = re.compile(r"\b(?:it|test|describe|context)\.only\s*\(|\bf(?:it|describe)\s*\(")
_SKIPPED = re.compile(
    r"\b(?:it|test|describe|context)\.skip\s*\(|\bx(?:it|describe|test)\s*\("
    r"|@pytest\.mark\.skip\b|@unittest\.skip\b"
)
_CI_RUNS_TESTS = re.compile(
    r"\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?test\b|\bnpx\s+(?:vitest|jest|playwright|cypress)\b"
    r"|\bvitest\b|\bjest\b|\bpytest\b|\bplaywright\s+test\b|\bcypress\s+run\b|\bunittest\b"
    r"|\bmake\s+test\b|\btox\b|\bnox\b|\buv\s+run\s+pytest\b",
)
_CI_FILE = re.compile(
    r"^(?:\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.yml|\.circleci/config\.yml"
    r"|bitbucket-pipelines\.yml|azure-pipelines\.yml|\.travis\.yml)$"
)
# Pages where a broken flow loses users or money.
_CRITICAL_PAGE = re.compile(
    r"(?:^|/)(?:login|log-in|signin|sign-in|signup|sign-up|register|checkout|billing|"
    r"subscribe|pricing|reset-password|forgot-password)(?:/|\.|$)",
    re.I,
)
# Pages a user sees: components and route files, not DTOs or controllers named login.ts.
_UI_EXT = {".tsx", ".jsx", ".vue", ".svelte", ".astro"}
_GENERIC_STEMS = {"route", "index", "page", "actions", "action", "main", "app", "server", "api"}


def _is_test_file(rel: str) -> bool:
    parts = rel.split("/")
    return bool(_TEST_FILE.search(parts[-1])) or any(p in _TEST_DIRS for p in parts[:-1])


def _python_project(project: Project) -> str:
    """Text of the Python dependency files, or "" when this isn't a Python project."""
    text = ""
    for path in project.files:
        if (
            path.name
            in {
                "pyproject.toml",
                "requirements.txt",
                "requirements-dev.txt",
                "setup.cfg",
                "Pipfile",
                "setup.py",
            }
            and path.parent == project.root
        ):
            text += _read(path) + "\n"
    return text


def _scripts(package_json: str) -> dict[str, str]:
    try:
        data = json.loads(package_json or "{}")
    except ValueError:
        return {}
    scripts = data.get("scripts") if isinstance(data, dict) else None
    return {k: str(v) for k, v in scripts.items()} if isinstance(scripts, dict) else {}


def _deps(package_json: str) -> str:
    """Dependency names, one per line, from every dependency section of package.json."""
    try:
        data = json.loads(package_json or "{}")
    except ValueError:
        return ""
    names: list[str] = []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        value = data.get(section) if isinstance(data, dict) else None
        if isinstance(value, dict):
            names.extend(value)
    return "\n".join(names)


_SCRIPT_RUNNERS = (
    (re.compile(r"\bnode\b[^&|;]*--test\b"), "node:test"),
    (re.compile(r"\btsx\b[^&|;]*--test\b"), "node:test"),
    (re.compile(r"\bbun\s+test\b"), "bun test"),
    (re.compile(r"\bdeno\s+test\b"), "deno test"),
)


def detect_runner(project: Project) -> str:
    test_script = _scripts(project.package_json).get("test", "")
    for pattern, name in _SCRIPT_RUNNERS:
        if pattern.search(test_script):
            return name
    deps = _deps(project.package_json)
    for dep, name in _JS_RUNNERS:
        if any(line == dep or line.startswith(dep) for line in deps.splitlines()):
            return name
    if re.search(r"\bpytest\b", _python_project(project)):
        return "pytest"
    return ""


def _setup_hint(project: Project, runner: str) -> str:
    if runner:
        return f"Use {runner}, which is already set up."
    if project.package_json:
        return (
            'Set up vitest first: npm i -D vitest, and add "test": "vitest run" to the scripts in '
            "package.json."
        )
    return "Set up pytest first: add pytest to your dev dependencies."


def _finding(
    rule: str,
    title: str,
    severity: Severity,
    file: str,
    line: int,
    detail: str,
    fix: str,
    *,
    confidence: str = "high",
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        scan_type=ScanType.SAST,
        tool=TOOL,
        file=file,
        line=line,
        rule_id=rule,
        description=detail,
        fix_guidance=fix,
        confidence=confidence,
        cwe="CWE-1164" if rule == "tests-no-assertions" else "",
    )


def _mutations(project: Project, sources: list[Path]) -> list[tuple[str, int, str]]:
    """(file, line, what) for code that changes data: route handlers, server actions, endpoints."""
    out: list[tuple[str, int, str]] = []
    for path in sources:
        rel = _rel(project, path)
        text = _read(path)
        if not text:
            continue
        if path.suffix == ".py":
            m = _PY_MUTATION_ROUTE.search(text)
            if m and _PY_DATA_CHANGE.search(text):
                out.append((rel, _line_of(text, m.start()), "endpoint"))
            continue
        if not _DATA_CHANGE.search(text):
            continue
        stem = path.name.rsplit(".", 1)[0]
        m = _ROUTE_MUTATION.search(text)
        if m and (stem == "route" or "/api/" in f"/{rel}"):
            out.append((rel, _line_of(text, m.start()), f"{m.group(1) or m.group(2)} handler"))
        elif rel.startswith(("pages/api/", "src/pages/api/")) and "export default" in text:
            out.append((rel, _line_of(text, text.index("export default")), "API route"))
        elif _USE_SERVER.search(text[:500]):
            m = _SERVER_ACTION.search(text)
            if m:
                out.append((rel, _line_of(text, m.start()), "server action"))
    return out


def _key_for(rel: str) -> str:
    """What a test for this file would mention: `orders` for app/api/orders/route.ts."""
    parts = rel.split("/")
    stem = parts[-1].rsplit(".", 1)[0]
    if stem in _GENERIC_STEMS:
        named = [
            p
            for p in parts[:-1]
            if not p.startswith(("(", "[")) and p not in {"app", "src", "api", "pages"}
        ]
        return named[-1] if named else ""
    return stem


def find_testing_gaps(target: str) -> tuple[list[Finding], dict[str, object]]:
    project = discover(Path(target))
    py_deps = _python_project(project)
    if not project.package_json and not py_deps:
        return [], {"app": False}

    rels = {path: _rel(project, path) for path in project.files}
    tests = [p for p, r in rels.items() if p.suffix in _SOURCE_EXT and _is_test_file(r)]
    sources = [
        p
        for p, r in rels.items()
        if p.suffix in _SOURCE_EXT
        and not _is_test_file(r)
        and not p.name.endswith((".d.ts", ".config.ts", ".config.js", ".config.mjs"))
    ]
    runner = detect_runner(project)
    setup = _setup_hint(project, runner)
    findings: list[Finding] = []
    metadata: dict[str, object] = {
        "app": True,
        "runner": runner,
        "test_files": len(tests),
        "source_files": len(sources),
    }

    # --- no runner / no tests / placeholder script --------------------------------------------
    scripts = _scripts(project.package_json)
    if project.package_json and _PLACEHOLDER_TEST.search(scripts.get("test", "")):
        findings.append(
            _finding(
                "tests-placeholder-script",
                '"npm test" is the placeholder script — no tests run',
                Severity.MEDIUM,
                "package.json",
                _line_of(project.package_json, project.package_json.find('"test"')),
                'The test script still says "Error: no test specified", so npm test and any CI '
                "step that calls it check nothing.",
                f'{setup} Point the "test" script at it (e.g. "test": "vitest run").',
            )
        )
    if not tests and len(sources) >= 3:
        findings.append(
            _finding(
                "tests-none",
                f"No tests: {len(sources)} source files and not one test file",
                Severity.MEDIUM,
                "package.json" if project.package_json else "",
                0,
                "Every change your AI tool makes could break login, payments or saving data, and "
                "nothing would tell you before your users do.",
                f"{setup} Start with the code that saves or deletes data, then the login flow.",
            )
        )
    elif tests and not runner and project.package_json and not py_deps:
        findings.append(
            _finding(
                "tests-no-runner",
                "Test files exist but no test runner is installed",
                Severity.LOW,
                "package.json",
                0,
                "package.json has no vitest, jest, mocha or Playwright, so these tests probably "
                "can't run.",
                setup,
            )
        )

    # --- untested code that changes data ------------------------------------------------------
    # A test "covers" a file when its name or its text mentions it (orders.test.ts, '/api/orders').
    test_text = "\n".join(rels[p] + "\n" + _read(p) for p in tests)
    for rel, line, what in _mutations(project, sources):
        key = _key_for(rel)
        if tests and key and re.search(rf"\b{re.escape(key)}\b", test_text):
            continue
        findings.append(
            _finding(
                "tests-untested-mutation",
                f"This {what} changes data and has no test",
                Severity.MEDIUM,
                rel,
                line,
                "Code that writes to your database is where a small AI edit does the most damage: "
                "a dropped auth check or a wrong filter deletes or leaks other users' data.",
                f"Write tests for {rel} ({what}). {setup} Cover: a request with no logged-in user "
                "is rejected (401/403); a user can't change another user's records; a valid "
                "request by the owner works. Mock the database client.",
            )
        )

    # --- test quality ---------------------------------------------------------------------------
    for path in tests:
        rel = rels[path]
        text = _read(path)
        is_py = path.suffix == ".py"
        cases = _PY_TEST_CASE.search(text) if is_py else _JS_TEST_CASE.search(text)
        if cases and not _ASSERTION.search(text):
            findings.append(
                _finding(
                    "tests-no-assertions",
                    "Test file has tests that check nothing (no expect / assert)",
                    Severity.LOW,
                    rel,
                    _line_of(text, cases.start()),
                    "A test without an assertion passes whatever the code does. AI tools sometimes "
                    "write these to make a failing suite go green.",
                    "Add expect(...) / assert checks on the result, the response status and what "
                    "was written to the database.",
                )
            )
        m = _FOCUSED.search(text)
        if m:
            findings.append(
                _finding(
                    "tests-focused",
                    ".only left in a test — every other test is silently skipped",
                    Severity.MEDIUM,
                    rel,
                    _line_of(text, m.start()),
                    "With .only (or fit / fdescribe), the runner runs just this test and reports "
                    "success for the whole suite.",
                    "Remove .only. Many runners can fail on it in CI (vitest --allowOnly=false, "
                    "jest --ci with eslint-plugin-jest no-focused-tests).",
                )
            )
        m = _SKIPPED.search(text)
        if m:
            findings.append(
                _finding(
                    "tests-skipped",
                    "Skipped test left in",
                    Severity.LOW,
                    rel,
                    _line_of(text, m.start()),
                    "Skipped tests are often ones that started failing; the bug they found is "
                    "still there.",
                    "Fix the test or the code it found broken, then remove the skip.",
                    confidence="low",
                )
            )

    # --- CI -------------------------------------------------------------------------------------
    ci_files = [p for p, r in rels.items() if _CI_FILE.match(r)]
    if tests and ci_files and not any(_CI_RUNS_TESTS.search(_read(p)) for p in ci_files):
        first = rels[sorted(ci_files)[0]]
        findings.append(
            _finding(
                "tests-not-in-ci",
                "CI never runs your tests",
                Severity.LOW,
                first,
                0,
                "The pipeline deploys without running the test suite, so a change that breaks "
                "tests still ships.",
                "Add a step before deploy that runs the tests (e.g. npm ci && npm test, or "
                "pytest) and fails the job when they fail.",
            )
        )

    # --- end to end -------------------------------------------------------------------------------
    deps = _deps(project.package_json)
    has_e2e = any(d in deps for d in _E2E_DEPS) or any(
        "e2e" in rels[p].split("/") or "cypress" in rels[p] or "playwright" in rels[p]
        for p in tests
    )
    pages = sorted(
        r
        for p, r in rels.items()
        if p.suffix in _UI_EXT and p in sources and _CRITICAL_PAGE.search(r)
    )
    if project.package_json and pages and not has_e2e:
        findings.append(
            _finding(
                "tests-no-e2e",
                "No end-to-end test for login, signup or checkout",
                Severity.LOW,
                pages[0],
                0,
                f"The app has {len(pages)} page(s) for signing in or paying "
                f"({', '.join(pages[:3])}{'…' if len(pages) > 3 else ''}) and no browser test "
                "that walks through them.",
                "Add Playwright (npm init playwright@latest) and one test per flow: sign up, log "
                "in, log out, and pay with a test card in your payment provider's test mode. Use "
                "test accounts, never real customer data.",
            )
        )
    return findings, metadata


async def run_test_checks(target: str) -> ScanResult:
    result = ScanResult(tool=TOOL, scan_type=ScanType.SAST, target=target)
    try:
        findings, metadata = await asyncio.to_thread(find_testing_gaps, target)
    except Exception as exc:  # never break a scan
        result.errors.append(f"argus-tests error: {exc}")
        return result
    result.findings.extend(findings)
    result.metadata.update(metadata)
    return result
