"""Batch fixes: one diff preview, one confirmation (#40)."""

from __future__ import annotations

import json
import os
import textwrap
from pathlib import Path

import pytest
import yaml

from argus.remediation import github_actions
from argus.tools import batch_fix as bf
from argus.tools.batch_fix import FixItem, batch_fix

SHA = "08eba0b27e820071cde6df949e0beb9ba4906955"
PIN = "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag"
INJ = "yaml.github-actions.security.run-shell-injection.run-shell-injection"

WORKFLOW = textwrap.dedent("""\
    name: ci
    on: [pull_request]
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - name: Greet
            run: echo "${{ github.head_ref }}"
          - uses: actions/checkout@v4
          - uses: actions/setup-node@v4
    """)


@pytest.fixture(autouse=True)
def fake_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve(action: str, ref: str) -> str | None:
        return SHA if ref == "v4" else None

    monkeypatch.setattr(github_actions, "resolve_ref", resolve)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    wf = tmp_path / ".github" / "workflows" / "ci.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text(WORKFLOW)
    return tmp_path


def items() -> list[FixItem]:
    f = ".github/workflows/ci.yml"
    # The injection (line 8) adds env: lines; the pins (lines 9, 10) sit below it, so the
    # batch must fix bottom-up for their line numbers to stay right.
    return [
        FixItem(f, "opengrep", "sast", INJ, 8),
        FixItem(f, "opengrep", "sast", PIN, 9),
        FixItem(f, "opengrep", "sast", PIN, 10),
        FixItem("app.py", "gitleaks", "secrets", "aws-key", 3),  # guidance only: left out
    ]


@pytest.mark.asyncio
async def test_preview_changes_nothing_and_shows_one_diff(repo: Path) -> None:
    before = (repo / ".github/workflows/ci.yml").read_text()
    out = await batch_fix(str(repo), items())
    assert (repo / ".github/workflows/ci.yml").read_text() == before
    assert out["applied"] is False and out["confirm_token"]
    assert out["fixable"] == 3 and out["files"] == [".github/workflows/ci.yml"]
    assert out["diff"].count("--- a/.github/workflows/ci.yml") == 1
    assert f"+      - uses: actions/checkout@{SHA} # v4" in out["diff"]
    assert f"+      - uses: actions/setup-node@{SHA} # v4" in out["diff"]
    assert '+        run: echo "${HEAD_REF}"' in out["diff"]
    assert not any(r.get("rule_id") == "aws-key" for r in out["results"])


@pytest.mark.asyncio
async def test_apply_needs_the_matching_token(repo: Path) -> None:
    path = repo / ".github/workflows/ci.yml"
    before = path.read_text()
    preview = await batch_fix(str(repo), items())

    refused = await batch_fix(str(repo), items(), apply=True, confirm_token="wrong")
    assert refused["applied"] is False and path.read_text() == before

    done = await batch_fix(str(repo), items(), apply=True, confirm_token=preview["confirm_token"])
    assert done["applied"] is True
    steps = yaml.safe_load(path.read_text())["jobs"]["build"]["steps"]
    assert steps[0]["env"] == {"HEAD_REF": "${{ github.head_ref }}"}
    assert (
        steps[1]["uses"] == f"actions/checkout@{SHA}"
        and steps[2]["uses"] == f"actions/setup-node@{SHA}"
    )


@pytest.mark.asyncio
async def test_file_changed_after_preview_is_not_overwritten(repo: Path) -> None:
    path = repo / ".github/workflows/ci.yml"
    preview = await batch_fix(str(repo), items())
    path.write_text(path.read_text() + "# edited by someone else\n")
    out = await batch_fix(str(repo), items(), apply=True, confirm_token=preview["confirm_token"])
    assert out["applied"] is False and "doesn't match" in out["message"]
    assert path.read_text().endswith("# edited by someone else\n")


@pytest.mark.asyncio
async def test_outside_target_and_missing_files(repo: Path, tmp_path_factory) -> None:
    other = tmp_path_factory.mktemp("other") / "x.yml"
    other.write_text(WORKFLOW)
    out = await batch_fix(
        str(repo),
        [
            FixItem(str(other), "opengrep", "sast", PIN, 9),
            FixItem("gone.yml", "opengrep", "sast", PIN, 1),
        ],
    )
    statuses = {r["file"]: r["status"] for r in out["results"]}
    assert statuses[str(other)] == "refused" and statuses["gone.yml"] == "skipped"
    assert out["diff"] == "" and out["confirm_token"] == ""


@pytest.mark.asyncio
async def test_tool_fixes_run_on_a_sibling_copy(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = repo / "src" / "app.js"
    src.parent.mkdir()
    src.write_text("eval(userInput);\n")
    os.chmod(src, 0o755)
    seen: list[Path] = []

    async def fake_eslint(file_path: str, timeout: int):
        p = Path(file_path)
        seen.append(p)
        assert p.parent == src.parent and p != src  # same folder, not the real file
        p.write_text("JSON.parse(userInput);\n")
        return True, "fixed"

    monkeypatch.setattr(bf, "_run_eslint_fix", fake_eslint)
    monkeypatch.setattr(bf, "_autofix_available", lambda tool, scan_type, rule_id="": True)
    item = [
        FixItem("src/app.js", "eslint-security", "sast", "security/detect-eval-with-expression", 1)
    ]
    preview = await batch_fix(str(repo), item)
    assert src.read_text() == "eval(userInput);\n" and not seen[0].exists()
    assert "+JSON.parse(userInput);" in preview["diff"]
    await batch_fix(str(repo), item, apply=True, confirm_token=preview["confirm_token"])
    assert src.read_text() == "JSON.parse(userInput);\n"
    assert os.stat(src).st_mode & 0o777 == 0o755
    assert sorted(p.name for p in src.parent.iterdir()) == ["app.js"]  # no temp files left


@pytest.mark.asyncio
async def test_mcp_tool_with_a_scan_report(repo: Path) -> None:
    from argus.server import _handle_apply_fixes

    report = {
        "results": [
            {
                "tool": "opengrep",
                "scan_type": "sast",
                "findings": [
                    {
                        "file": ".github/workflows/ci.yml",
                        "line": 9,
                        "rule_id": PIN,
                        "tool": "opengrep",
                    },
                    {
                        "file": ".github/workflows/ci.yml",
                        "line": 10,
                        "rule_id": PIN,
                        "tool": "opengrep",
                    },
                ],
            }
        ]
    }
    out = json.loads(
        (await _handle_apply_fixes({"target": str(repo), "scan_result_json": json.dumps(report)}))[
            0
        ].text
    )
    assert out["fixable"] == 2 and out["applied"] is False
    applied = json.loads(
        (
            await _handle_apply_fixes(
                {
                    "target": str(repo),
                    "scan_result_json": json.dumps(report),
                    "apply": True,
                    "confirm_token": out["confirm_token"],
                }
            )
        )[0].text
    )
    assert applied["applied"] is True
    empty = json.loads((await _handle_apply_fixes({"target": str(repo)}))[0].text)
    assert "error" in empty
