"""`argus unit-test`: is the app tested? (#276)

Reads the repo (nothing is run) and reports a 0-100 testing score, what is missing, and for
each item a prompt that asks your AI tool to write the tests: which runner to use, which cases
to cover, and to mock databases, payments and email. Separate from `argus scan vibe` because
missing tests aren't a vulnerability.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from argus.redaction import redact_text
from argus.vibe_report import _excerpt, _explanation, _penalty, mask_for_prompt

WEIGHT = {"critical": 30.0, "high": 20.0, "medium": 15.0, "low": 6.0}
_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
VERDICTS = (
    (80, "Well tested", "The basics are covered."),
    (50, "Partly tested", "Add tests for the items below, starting at the top."),
    (20, "Barely tested", "Most of what could break has no test."),
    (0, "No real tests", "Nothing checks that your app still works after a change."),
)
_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}


async def run_unit_test_scan(target: str) -> list[Any]:
    from argus.tools.testing_checks import run_test_checks

    return [await run_test_checks(target)]


def tests_prompt(item: dict[str, Any], excerpt: str) -> str:
    where = f"{item['file']} (line {item['line']})" if item["line"] else item["file"] or "project"
    parts = ["Improve the tests in my app.", "", f"Where: {where}", f"Problem: {item['title']}"]
    if item["explanation"]:
        parts.append(item["explanation"])
    if excerpt:
        parts += ["", "Code:", "```", excerpt, "```"]
    if item["fix"]:
        parts += ["", f"What to do: {item['fix']}"]
    parts += [
        "",
        "Tests must check real behaviour with expect / assert, not just run the code. Don't call "
        "real databases, payment providers or email services: mock them or use test mode. Use "
        "made-up test data, never real customer data or real keys. Run the tests and show me "
        "they pass.",
    ]
    return "\n".join(parts)


def tests_summary(
    report: dict[str, Any], root: str | Path, *, redact_pii: bool = False
) -> dict[str, Any]:
    base = Path(root)
    base = base if base.is_dir() else base.parent
    meta: dict[str, Any] = {}
    items: list[dict[str, Any]] = []
    for result in report.get("results", []):
        if result.get("tool") == "argus-tests":
            meta = result.get("metadata") or {}
        for f in result.get("findings", []):
            severity = str(f.get("severity", "")).lower()
            if severity not in WEIGHT or not str(f.get("rule_id", "")).startswith("tests-"):
                continue
            items.append(
                {
                    "severity": severity,
                    "confidence": f.get("confidence") or "medium",
                    "rule_id": f.get("rule_id", ""),
                    "title": mask_for_prompt(f.get("title", "")),
                    "file": f.get("file", ""),
                    "line": int(f.get("line") or 0),
                    "explanation": _explanation(f.get("description", "")),
                    "fix": mask_for_prompt(f.get("fix_guidance", "")).strip(),
                }
            )
    items.sort(
        key=lambda i: (_ORDER[i["severity"]], i["confidence"] == "low", i["file"], i["line"])
    )
    if not meta.get("app"):
        return {
            "score": None,
            "verdict": "Not an app project",
            "detail": "No package.json or Python project file found, so there is nothing to check.",
            "runner": "",
            "test_files": 0,
            "source_files": 0,
            "items": [],
        }
    score = max(0, round(100 - _penalty(items, WEIGHT)))
    if any(i["rule_id"] in {"tests-none", "tests-placeholder-script"} for i in items):
        score = min(score, 40 if meta.get("test_files") else 10)
    verdict, detail = next((v, d) for floor, v, d in VERDICTS if score >= floor)
    for item in items:
        prompt = tests_prompt(item, _excerpt(base, item["file"], item["line"]))
        if redact_pii:
            prompt, _ = redact_text(prompt)
        item["prompt"] = prompt
    return {
        "score": score,
        "verdict": verdict,
        "detail": detail,
        "runner": meta.get("runner") or "",
        "test_files": meta.get("test_files", 0),
        "source_files": meta.get("source_files", 0),
        "items": items,
    }


def format_tests_markdown(summary: dict[str, Any], target: str = "") -> str:
    lines = [f"# Unit test check{f': {Path(target).name}' if target else ''}", ""]
    if summary["score"] is None:
        return "\n".join(lines + [f"{summary['verdict']}. {summary['detail']}"]) + "\n"
    runner = summary["runner"] or "no test runner"
    lines += [
        f"**Testing score: {summary['score']}/100. {summary['verdict']}.** {summary['detail']}",
        "",
        f"{summary['test_files']} test file(s) for {summary['source_files']} source file(s), "
        f"{runner}.",
    ]
    if not summary["items"]:
        lines += ["", "Nothing missing that these checks look for."]
    for n, item in enumerate(summary["items"], 1):
        where = f"{item['file']}:{item['line']}" if item["line"] else item["file"]
        maybe = " (worth a look, may be fine)" if item["confidence"] == "low" else ""
        lines += ["", f"## {n}. {_ICON[item['severity']]} {item['title']}{maybe}"]
        if where:
            lines += ["", f"`{where}`"]
        if item["explanation"]:
            lines += ["", item["explanation"]]
        if item["fix"]:
            lines += ["", f"**What to do:** {item['fix']}"]
        lines += [
            "",
            "<details><summary>Prompt to write the tests</summary>",
            "",
            "````text",
            item["prompt"],
            "````",
            "",
            "</details>",
        ]
    return "\n".join(lines) + "\n"
