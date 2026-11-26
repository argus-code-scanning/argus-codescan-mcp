"""`argus scan vibe` / MCP scan_vibe: score, verdict and fix prompts (#273)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus import cli
from argus.vibe_report import mask_for_prompt, vibe_summary

OPENAI_KEY = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2"


@pytest.fixture
def app(tmp_path: Path) -> Path:
    files = {
        "package.json": '{"dependencies": {"next": "15", "@supabase/supabase-js": "^2"}}',
        ".env.local": f"NEXT_PUBLIC_OPENAI_API_KEY={OPENAI_KEY}\n",
        "supabase/migrations/001.sql": (
            "create table public.orders (id serial primary key, user_id uuid);\n"
            'create policy "all" on public.notes for update using (true);\n'
        ),
        "app/chat.tsx": (
            "'use client'\n"
            f'const openai = new OpenAI({{ apiKey: "{OPENAI_KEY}", dangerouslyAllowBrowser: true }});\n'
        ),
        "lib/hash.ts": "import { createHash } from 'crypto'\nexport const h = createHash('md5')\n",
        "tests/fixture.test.ts": "const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY\n",
    }
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    return tmp_path


def _finding(severity: str, rule: str, **extra: object) -> dict:
    return {"severity": severity, "rule_id": rule, "title": rule, "file": "", "line": 0, **extra}


def _report(*findings: dict) -> dict:
    return {"results": [{"tool": "t", "findings": list(findings)}]}


def test_score_and_verdict(tmp_path: Path) -> None:
    assert vibe_summary(_report(), tmp_path)["score"] == 100
    medium = vibe_summary(_report(_finding("medium", "a"), _finding("medium", "b")), tmp_path)
    assert medium["score"] == 90 and medium["verdict"] == "Looks good to launch"
    # One critical caps the score below 40 whatever else is found.
    critical = vibe_summary(_report(_finding("critical", "key")), tmp_path)
    assert critical["score"] <= 39 and critical["verdict"].startswith("Stop")
    # A low-confidence critical doesn't cap it.
    assert (
        vibe_summary(_report(_finding("critical", "k", confidence="low")), tmp_path)["score"] > 90
    )


def test_repeats_of_one_rule_cost_less(tmp_path: Path) -> None:
    same = vibe_summary(_report(*[_finding("high", "rls", line=n) for n in range(1, 31)]), tmp_path)
    assert same["score"] == 100 - 36  # three times one high finding
    assert len(same["items"]) == 30


def test_noise_and_test_files_are_left_out(tmp_path: Path) -> None:
    summary = vibe_summary(
        _report(
            _finding("medium", "weak-crypto"),
            _finding("high", "pci-pan-in-source"),
            _finding("medium", "pii-hardcoded-email"),
            _finding("high", "vibe-x", context="test"),
            _finding("info", "note"),
            _finding("high", "vibe-y"),
        ),
        tmp_path,
    )
    assert [i["rule_id"] for i in summary["items"]] == ["vibe-y"]
    assert summary["not_shipped"] == 1


def test_prompt_masks_secrets(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(f"OPENAI_API_KEY={OPENAI_KEY}\nDEBUG=1\n")
    (tmp_path / "a.ts").write_text(f'const k = "{OPENAI_KEY}"\n')
    report = _report(
        _finding("high", "env", file=".env", line=1, fix_guidance="Rotate it."),
        _finding("high", "src", file="a.ts", line=1),
    )
    summary = vibe_summary(report, tmp_path)
    for item in summary["items"]:
        assert OPENAI_KEY not in item["prompt"]
        assert "Fix this security issue" in item["prompt"]
    assert "OPENAI_API_KEY=<value hidden>" in summary["items"][0]["prompt"]
    assert "What to change: Rotate it." in summary["items"][0]["prompt"]


def test_mask_for_prompt_shapes() -> None:
    text = mask_for_prompt(
        "a=sk-ant-api03-abcdefghijklmnopqrstuv b=AIzaSyA1234567890abcdefghijklmnopqrstuv"
    )
    assert "sk-ant" not in text and "AIza" not in text


def test_excerpt_stays_inside_the_project(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-secret.txt"
    outside.write_text("secret\n")
    report = _report(_finding("high", "x", file="../outside-secret.txt", line=1))
    assert "Code:" not in vibe_summary(report, tmp_path)["items"][0]["prompt"]


def test_cli_scan_vibe(app: Path, capsys) -> None:
    code = cli.main(["scan", "vibe", str(app), "--fail-on", "high"])
    out = capsys.readouterr().out
    assert "Safety score:" in out and "/100" in out
    assert "public env variable" in out
    assert "Prompt for your AI tool" in out
    assert OPENAI_KEY not in out
    assert "Weak cryptography" not in out
    assert code == 1


def test_cli_scan_vibe_json(app: Path, capsys) -> None:
    cli.main(["scan", "vibe", str(app), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    vibe = report["vibe"]
    assert 0 <= vibe["score"] < 70
    rules = {i["rule_id"] for i in vibe["items"]}
    assert {"vibe-public-env-secret", "vibe-supabase-table-without-rls"} <= rules
    assert "vibe-llm-key-in-browser" in rules
    assert all(OPENAI_KEY not in i["prompt"] for i in vibe["items"])


@pytest.mark.asyncio
async def test_mcp_scan_vibe(app: Path) -> None:
    from argus.server import _handle_scan_vibe

    out = await _handle_scan_vibe({"target": str(app)})
    assert "Safety score:" in out[0].text
    assert OPENAI_KEY not in out[0].text
    data = json.loads((await _handle_scan_vibe({"target": str(app), "format": "json"}))[0].text)
    assert data["vibe"]["items"]
