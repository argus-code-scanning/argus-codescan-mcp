"""Automated fixes for GitHub Actions findings (pinning, run-shell injection)."""

from __future__ import annotations

import textwrap

import pytest
import yaml

from argus.remediation import github_actions as gha
from argus.tools.fix import _autofix_available, apply_finding_fix

SHA = "08eba0b27e820071cde6df949e0beb9ba4906955"
PIN_RULE = "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag"
INJ_RULE = "yaml.github-actions.security.run-shell-injection.run-shell-injection"


async def fake_resolver(action: str, ref: str) -> str | None:
    return SHA if ref in {"v4", "v3", "main"} else None


def wf(s: str) -> str:
    return textwrap.dedent(s).lstrip("\n")


# --- pinning ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_pin_rewrites_tag_to_sha_with_comment() -> None:
    text = wf("""
        jobs:
          a:
            steps:
              - uses: actions/checkout@v4
              - uses: actions/setup-node@v4
        """)
    out = await gha.pin_action(text, 4, fake_resolver)
    assert out.ok
    assert f"      - uses: actions/checkout@{SHA} # v4\n" in out.text
    assert "actions/setup-node@v4\n" in out.text  # other lines untouched


@pytest.mark.asyncio
async def test_pin_keeps_quotes_and_replaces_old_comment() -> None:
    text = "      - uses: 'github/codeql-action/init@v3'  # old note\n"
    out = await gha.pin_action(text, 1, fake_resolver)
    assert out.ok
    assert out.text == f"      - uses: 'github/codeql-action/init@{SHA}' # v3\n"


@pytest.mark.asyncio
async def test_pin_refuses_when_unresolvable_or_already_pinned() -> None:
    out = await gha.pin_action("- uses: actions/checkout@v999\n", 1, fake_resolver)
    assert not out.ok and "Could not resolve" in out.message
    out = await gha.pin_action(f"- uses: actions/checkout@{SHA}\n", 1, fake_resolver)
    assert not out.ok and "already pinned" in out.message


@pytest.mark.asyncio
async def test_pin_ignores_local_and_docker_actions() -> None:
    assert not (await gha.pin_action("- uses: ./.github/actions/x\n", 1, fake_resolver)).ok
    assert not (await gha.pin_action("- uses: docker://alpine:3\n", 1, fake_resolver)).ok


# --- run-shell injection ---------------------------------------------------


def test_injection_block_run_moves_expressions_to_env() -> None:
    text = wf("""
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - name: Greet
                run: |
                  echo "Title: ${{ github.event.pull_request.title }}"
                  echo Branch ${{ github.head_ref }}
              - run: echo done
        """)
    out = gha.fix_run_injection(text, 6)
    assert out.ok, out.message
    assert 'echo "Title: ${PULL_REQUEST_TITLE}"' in out.text
    assert 'echo Branch "${HEAD_REF}"' in out.text
    assert "${{" not in out.text.split("env:")[0]  # nothing left in the script
    step = yaml.safe_load(out.text)["jobs"]["a"]["steps"][0]
    assert step["env"] == {
        "PULL_REQUEST_TITLE": "${{ github.event.pull_request.title }}",
        "HEAD_REF": "${{ github.head_ref }}",
    }
    assert yaml.safe_load(out.text)["jobs"]["a"]["steps"][1] == {"run": "echo done"}


def test_injection_dash_run_form_and_repeated_expression() -> None:
    text = wf("""
        steps:
          - run: echo ${{ github.head_ref }} && echo "${{ github.head_ref }}"
          - run: echo next
        """)
    out = gha.fix_run_injection(text, 2)
    assert out.ok, out.message
    steps = yaml.safe_load(out.text)["steps"]
    assert steps[0]["run"] == 'echo "${HEAD_REF}" && echo "${HEAD_REF}"'
    assert steps[0]["env"] == {"HEAD_REF": "${{ github.head_ref }}"}
    assert steps[1] == {"run": "echo next"}


def test_injection_adds_to_existing_env_without_name_clash() -> None:
    text = wf("""
        steps:
          - name: x
            env:
              HEAD_REF: keep-me
            run: echo ${{ github.head_ref }}
        """)
    out = gha.fix_run_injection(text, 5)
    assert out.ok, out.message
    step = yaml.safe_load(out.text)["steps"][0]
    assert step["env"] == {"HEAD_REF": "keep-me", "HEAD_REF_2": "${{ github.head_ref }}"}
    assert step["run"] == 'echo "${HEAD_REF_2}"'


def test_injection_inside_single_quotes_closes_and_reopens() -> None:
    text = "steps:\n  - run: echo 'ref=${{ github.ref_name }}'\n"
    out = gha.fix_run_injection(text, 2)
    assert out.ok, out.message
    assert yaml.safe_load(out.text)["steps"][0]["run"] == "echo 'ref='\"${REF_NAME}\"''"


def test_injection_refuses_non_posix_shell() -> None:
    text = wf("""
        steps:
          - shell: pwsh
            run: Write-Host ${{ github.head_ref }}
        """)
    out = gha.fix_run_injection(text, 3)
    assert not out.ok and "pwsh" in out.message


def test_injection_leaves_non_github_expressions() -> None:
    text = "steps:\n  - run: echo ${{ matrix.os }}\n"
    out = gha.fix_run_injection(text, 2)
    assert not out.ok


# --- apply_fix integration ---------------------------------------------------


def test_autofix_available_for_gha_rules_regardless_of_tool() -> None:
    assert _autofix_available("opengrep", "sast", PIN_RULE)
    assert _autofix_available("opengrep", "sast", INJ_RULE)
    assert not _autofix_available("opengrep", "sast", "some.other.rule")


@pytest.mark.asyncio
async def test_apply_fix_rewrites_workflow_only_when_apply(tmp_path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    path = wf_dir / "ci.yaml"
    original = "steps:\n  - run: echo ${{ github.head_ref }}\n"
    path.write_text(original)

    preview = await apply_finding_fix(
        target=str(tmp_path),
        file=".github/workflows/ci.yaml",
        tool="opengrep",
        rule_id=INJ_RULE,
        line=2,
        apply=False,
    )
    assert preview["autofix_available"] and not preview["applied"]
    assert path.read_text() == original

    done = await apply_finding_fix(
        target=str(tmp_path),
        file=".github/workflows/ci.yaml",
        tool="opengrep",
        rule_id=INJ_RULE,
        line=2,
        apply=True,
    )
    assert done["applied"], done["message"]
    assert yaml.safe_load(path.read_text())["steps"][0]["env"] == {
        "HEAD_REF": "${{ github.head_ref }}"
    }
