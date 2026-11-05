"""GitHub Actions: workflow discovery, unpinned actions and script injection (issues #143, #144)."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages import scan_directory
from argus_languages.discover import classify_file
from argus_languages.rules_loader import RULE_FILES, load_rules_from_files

RULES = {
    "gha-action-pinned-to-branch",
    "gha-third-party-action-not-pinned",
    "gha-first-party-action-not-pinned",
    "gha-docker-action-not-pinned",
    "gha-script-injection",
    "gha-checkout-pr-head",
    "gha-pull-request-target-trigger",
    "gha-permissions-write-all",
}
SHA = "a284dc1814e3fd07f2e34267fc8f81227ed29fb8"
DIGEST = "sha256:" + "a" * 64


def _findings(tmp_path: Path, relative: str, code: str) -> dict[str, str]:
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code)
    return {
        f.rule_id: str(f.severity.value)
        for f in scan_directory(tmp_path).findings
        if f.rule_id in RULES
    }


WORKFLOW = ".github/workflows/ci.yml"


def test_rule_pack_is_registered_and_complete() -> None:
    assert "github-actions.yaml" in RULE_FILES
    rules = load_rules_from_files(("github-actions.yaml",))
    assert {r.id for r in rules} == RULES
    for rule in rules:
        assert rule.fix_guidance, f"{rule.id} needs fix_guidance"
        assert rule.languages == ["github-actions"]


@pytest.mark.parametrize(
    ("relative", "expected"),
    [
        (".github/workflows/ci.yml", "github-actions"),
        (".github/workflows/release.yaml", "github-actions"),
        ("packages/app/.github/workflows/ci.yml", "github-actions"),
        ("action.yml", "github-actions"),
        (".github/actions/setup/action.yaml", "github-actions"),
        # Other YAML under .github, and workflow-looking folders elsewhere, are not workflows
        (".github/dependabot.yml", None),
        (".github/ISSUE_TEMPLATE/bug.yml", None),
        ("docs/workflows/ci.yml", None),
        ("config/settings.yml", None),
    ],
)
def test_workflow_files_are_discovered_as_their_own_type(
    tmp_path: Path, relative: str, expected: str | None
) -> None:
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "name: x\non: push\njobs: {}\n"
    path.write_text(content)
    assert classify_file(path, tmp_path, content) == expected


def test_only_the_github_dot_directory_is_scanned(tmp_path: Path) -> None:
    line = "      - uses: some-org/deploy@main\n"
    assert _findings(tmp_path, ".github/workflows/ci.yml", line) == {
        "gha-action-pinned-to-branch": "high"
    }
    other = tmp_path / "other"
    other.mkdir()
    assert _findings(other, ".cache/workflows/ci.yml", line) == {}
    assert _findings(other, ".hidden/.github/workflows/ci.yml", line) == {}


def test_generic_code_rules_do_not_apply_to_workflows(tmp_path: Path) -> None:
    # The quoted secret_key line is what the generic hardcoded-password rule matches in code.
    code = 'jobs:\n  a:\n    steps:\n      - run: secret_key = "abcdefghijklmnop1234"\n'
    found = {f.rule_id for f in _scan(tmp_path, code)}
    assert "hardcoded-password" not in found


def _scan(tmp_path: Path, code: str):
    path = tmp_path / WORKFLOW
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code)
    return scan_directory(tmp_path).findings


@pytest.mark.parametrize(
    ("code", "rule", "severity"),
    [
        # #143: pinning
        ("      - uses: some-org/deploy@main", "gha-action-pinned-to-branch", "high"),
        ("      - uses: actions/checkout@main", "gha-action-pinned-to-branch", "high"),
        ("      - uses: owner/repo@master", "gha-action-pinned-to-branch", "high"),
        (
            "      - uses: tj-actions/changed-files@v45",
            "gha-third-party-action-not-pinned",
            "medium",
        ),
        (
            "      - uses: pypa/gh-action-pypi-publish@release/v1",
            "gha-third-party-action-not-pinned",
            "medium",
        ),
        ("        uses: codecov/codecov-action@v4", "gha-third-party-action-not-pinned", "medium"),
        ("      - uses: actions/checkout@v4", "gha-first-party-action-not-pinned", "low"),
        (
            "      - uses: github/codeql-action/upload-sarif@v4",
            "gha-first-party-action-not-pinned",
            "low",
        ),
        ("      - uses: docker://alpine:3.20", "gha-docker-action-not-pinned", "low"),
        # #144: injection and pwn requests
        (
            '      - run: echo "${{ github.event.pull_request.title }}"',
            "gha-script-injection",
            "high",
        ),
        ("        run: echo ${{ github.head_ref }}", "gha-script-injection", "high"),
        ('          echo "Issue: ${{ github.event.issue.body }}"', "gha-script-injection", "high"),
        (
            '          script: console.log("${{ github.event.issue.title }}")',
            "gha-script-injection",
            "high",
        ),
        (
            "          git commit -m '${{ github.event.head_commit.message }}'",
            "gha-script-injection",
            "high",
        ),
        (
            "          ref: ${{ github.event.pull_request.head.sha }}",
            "gha-checkout-pr-head",
            "medium",
        ),
        ("on: pull_request_target", "gha-pull-request-target-trigger", "low"),
        ("  pull_request_target:", "gha-pull-request-target-trigger", "low"),
        ("on: [push, pull_request_target]", "gha-pull-request-target-trigger", "low"),
        ("permissions: write-all", "gha-permissions-write-all", "medium"),
    ],
)
def test_vulnerable_workflow_lines_are_flagged(
    tmp_path: Path, code: str, rule: str, severity: str
) -> None:
    found = _findings(tmp_path, WORKFLOW, f"{code}\n")
    assert found.get(rule) == severity


@pytest.mark.parametrize(
    "code",
    [
        f"      - uses: tj-actions/changed-files@{SHA} # v45",
        f"      - uses: actions/checkout@{SHA}",
        "      - uses: ./.github/actions/local",
        "      - uses: ./.github/workflows/reusable.yml",
        f"      - uses: docker://alpine@{DIGEST}",
        "          TITLE: ${{ github.event.pull_request.title }}",
        '        run: echo "$TITLE"',
        "        if: ${{ contains(github.event.pull_request.title, 'wip') }}",
        '        run: echo "${{ github.sha }}"',
        '        run: echo "run ${{ github.run_id }}"',
        "      # run: echo ${{ github.head_ref }}",
        "          ref: main",
        "          ref: ${{ github.ref }}",
        "on: pull_request",
        "on: [push, pull_request]",
        "# on: pull_request_target",
        "permissions: read-all",
        "permissions:",
        "  contents: read",
    ],
)
def test_safe_workflow_lines_are_not_flagged(tmp_path: Path, code: str) -> None:
    assert _findings(tmp_path, WORKFLOW, f"{code}\n") == {}


def test_rules_only_apply_to_workflow_files(tmp_path: Path) -> None:
    cases = {
        "python": ("script.py", "      - uses: some-org/deploy@main\n"),
        "plain_yaml": ("docs/ci.yml", "      - uses: some-org/deploy@main\n"),
        "text": ("notes.txt", "permissions: write-all\n"),
    }
    for name, (relative, code) in cases.items():
        folder = tmp_path / name
        folder.mkdir()
        assert _findings(folder, relative, code) == {}, name
