"""`argus scan vibe`: a launch check for apps built mostly with AI tools (#273).

Runs only built-in checks, so it works with nothing else installed: the vibe pack (Supabase,
Firebase, public env secrets, unprotected routes), the native line rules (secrets, cookies,
injection), security headers, rate limiting, hallucinated / typosquatted packages and
personal data. The result is a 0-100 score, a one-line verdict, and for each finding a plain
explanation plus a prompt to paste into Cursor / Claude / Lovable / Bolt.

Prompts carry a short code excerpt with secret values masked: a prompt is text that leaves
the machine, and a key pasted into an AI chat is a leaked key.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

from argus.models import ScanResult
from argus.redaction import mask_secret_values, redact_text

SEVERITY_WEIGHT = {"critical": 25.0, "high": 12.0, "medium": 5.0, "low": 1.0}
_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
# Files that don't ship: shown in the count, not in the score.
_NOT_SHIPPED = {"test", "docs", "generated", "example"}

# Left out of the launch check: findings that are mostly noise in these apps or need a
# specialist to judge (MD5 for cache keys, ReDoS, card-number heuristics that hit map
# coordinates, contact emails on a public site, Supabase's own grants and plpgsql EXECUTE).
# `argus scan all` still reports them.
_SKIP_RULES = re.compile(
    r"^(?:weak-crypto|redos-|pci-|sql-grant-all$|db-sql-dynamic-exec$|gha-|malware-"
    r"|pii-hardcoded-(?:email|phone|name|address))"
)

# Plain fix advice for native rules that don't carry fix_guidance, by rule id prefix.
_FALLBACK_FIX = (
    (
        "xss-",
        "Don't insert HTML built from user data. Render text with React/Vue (no "
        "dangerouslySetInnerHTML / innerHTML), or clean it with DOMPurify first.",
    ),
    (
        "hardcoded-",
        "Move the value to a server-only environment variable, remove it from the "
        "code and git history, and rotate it.",
    ),
    (
        "sql",
        "Use parameterized queries (placeholders like $1 or ?) or your ORM's query "
        "builder; never paste user input into SQL text.",
    ),
    ("cors-", "Allow only your own site's origin instead of *."),
    ("open-redirect", "Only redirect to paths on your own site, or to a fixed list of URLs."),
    (
        "command-",
        "Don't build shell commands from user input; call the program with an "
        "argument list and validate the input.",
    ),
)

# Key shapes mask_secret_values doesn't know: OpenAI / Anthropic, Google, Supabase secret keys.
_EXTRA_SECRETS = re.compile(
    r"\bsk-(?:proj-|ant-[a-z0-9]+-)?[A-Za-z0-9_-]{16,}"
    r"|\bAIza[0-9A-Za-z_-]{35}\b"
    r"|\bsb_secret_[A-Za-z0-9_-]{16,}"
)
_ENV_LINE = re.compile(r"^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*).+$")

VERDICTS = (
    (90, "Looks good to launch", "No serious problems found by these checks."),
    (70, "Fix a few things before launch", "Fix the items below, starting at the top."),
    (40, "Not safe to launch yet", "Attackers could reach your data or your bill."),
    (0, "Stop: your app is exposed", "Fix the top items before anyone uses it."),
)


async def run_vibe_scan(target: str) -> list[ScanResult]:
    from argus.tools.abuse_controls import run_abuse_control_check
    from argus.tools.code import run_native_languages
    from argus.tools.pii import run_pii_scan
    from argus.tools.security_headers import run_security_headers_check
    from argus.tools.typosquats import run_typosquat_check
    from argus.tools.vibe_checks import run_vibe_checks

    return list(
        await asyncio.gather(
            run_vibe_checks(target),
            run_native_languages(target),
            run_security_headers_check(target),
            run_abuse_control_check(target),
            run_typosquat_check(target),
            run_pii_scan(target),
        )
    )


def mask_for_prompt(text: str, *, env_file: bool = False) -> str:
    """Remove secret values from text that will be pasted into an AI chat."""
    if env_file:
        text = "\n".join(_ENV_LINE.sub(r"\1<value hidden>", line) for line in text.splitlines())
    text, _ = mask_secret_values(text)
    return _EXTRA_SECRETS.sub("[REDACTED:SECRET]", text)


def _excerpt(root: Path, file: str, line: int, context: int = 2) -> str:
    if not file or line <= 0:
        return ""
    path = (root / file) if not Path(file).is_absolute() else Path(file)
    try:
        if not path.resolve().is_relative_to(root.resolve()):
            return ""
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return ""
    start, end = max(0, line - 1 - context), min(len(lines), line + context)
    env_file = path.name.startswith(".env")
    width = len(str(end))
    return "\n".join(
        f"{n + 1:>{width}} | {mask_for_prompt(lines[n][:200], env_file=env_file)}"
        for n in range(start, end)
    )


def fix_prompt(item: dict[str, Any], excerpt: str) -> str:
    where = f"{item['file']} (line {item['line']})" if item["line"] else item["file"] or "project"
    parts = [
        "Fix this security issue in my app.",
        "",
        f"File: {where}",
        f"Problem: {item['title']}",
    ]
    if item["explanation"]:
        parts.append(item["explanation"])
    if excerpt:
        parts += ["", "Code:", "```", excerpt, "```"]
    if item["fix"]:
        parts += ["", f"What to change: {item['fix']}"]
    parts += [
        "",
        "Change only what is needed and keep the app working. Never put secret values in code "
        "or in client-side env variables; read them from server-only environment variables. "
        "Tell me if a key has to be rotated.",
    ]
    return "\n".join(parts)


def _fallback_fix(rule_id: str) -> str:
    return next((fix for prefix, fix in _FALLBACK_FIX if rule_id.startswith(prefix)), "")


def _explanation(description: str) -> str:
    """Drop the native engine's bookkeeping lines (\"Language: typescript\", ignore hints)."""
    kept = [
        line
        for line in description.splitlines()
        if line.strip() and not line.startswith(("Language:", "To ignore", "Suppress"))
    ]
    return mask_for_prompt("\n".join(kept)).strip()


def _verdict(score: int) -> tuple[str, str]:
    for floor, verdict, detail in VERDICTS:
        if score >= floor:
            return verdict, detail
    return VERDICTS[-1][1], VERDICTS[-1][2]


def vibe_summary(
    report: dict[str, Any], root: str | Path, *, redact_pii: bool = False
) -> dict[str, Any]:
    """Score, verdict and one plain item (with a fix prompt) per finding that ships."""
    base = Path(root)
    base = base if base.is_dir() else base.parent
    seen: set[tuple[str, int, str]] = set()
    items: list[dict[str, Any]] = []
    not_shipped = 0
    for result in report.get("results", []):
        for f in result.get("findings", []):
            severity = str(f.get("severity", "")).lower()
            if severity not in SEVERITY_WEIGHT:
                continue
            if _SKIP_RULES.match(f.get("rule_id") or ""):
                continue
            if f.get("context") in _NOT_SHIPPED:
                not_shipped += 1
                continue
            key = (f.get("file", ""), int(f.get("line") or 0), f.get("rule_id") or f.get("title"))
            if key in seen:
                continue
            seen.add(key)
            items.append(
                {
                    "severity": severity,
                    "confidence": f.get("confidence") or "medium",
                    "rule_id": f.get("rule_id", ""),
                    "title": mask_for_prompt(f.get("title", "")),
                    "file": f.get("file", ""),
                    "line": int(f.get("line") or 0),
                    "explanation": _explanation(f.get("description", "")),
                    "fix": mask_for_prompt(
                        f.get("fix_guidance") or _fallback_fix(f.get("rule_id") or "")
                    ).strip(),
                }
            )
    items.sort(
        key=lambda i: (_ORDER[i["severity"]], i["confidence"] == "low", i["file"], i["line"])
    )

    # Each repeat of a rule costs a third of the first, up to three times one finding: 30 tables
    # without RLS are one mistake made 30 times, not 30 times the risk of one.
    per_rule: dict[str, float] = {}
    for item in items:
        weight = SEVERITY_WEIGHT[item["severity"]]
        if item["confidence"] == "low":
            weight /= 4
        rule = item["rule_id"] or item["title"]
        cost = weight if rule not in per_rule else weight / 3
        per_rule[rule] = min(per_rule.get(rule, 0.0) + cost, weight * 3)
    penalty = sum(per_rule.values())
    score = max(0, round(100 - penalty))
    if any(i["severity"] == "critical" and i["confidence"] != "low" for i in items):
        score = min(score, 39)
    verdict, detail = _verdict(score)

    for item in items:
        prompt = fix_prompt(item, _excerpt(base, item["file"], item["line"]))
        if redact_pii:
            prompt, _ = redact_text(prompt)
        item["prompt"] = prompt

    counts = {s: sum(1 for i in items if i["severity"] == s) for s in _ORDER}
    return {
        "score": score,
        "verdict": verdict,
        "detail": detail,
        "counts": counts,
        "not_shipped": not_shipped,
        "items": items,
    }


_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}


def format_vibe_markdown(summary: dict[str, Any], target: str = "") -> str:
    counts = summary["counts"]
    lines = [
        f"# Launch check{f': {Path(target).name}' if target else ''}",
        "",
        f"**Safety score: {summary['score']}/100. {summary['verdict']}.** {summary['detail']}",
        "",
        " · ".join(f"{_ICON[s]} {counts[s]} {s}" for s in _ORDER),
    ]
    if summary["not_shipped"]:
        lines.append(
            f"\n{summary['not_shipped']} finding(s) in tests, docs or examples not counted."
        )
    if not summary["items"]:
        lines += [
            "",
            "No problems found by these checks. Keep secrets out of client code as you build.",
        ]
        return "\n".join(lines) + "\n"
    for n, item in enumerate(summary["items"], 1):
        where = f"`{item['file']}:{item['line']}`" if item["line"] else f"`{item['file']}`"
        maybe = " (worth a look, may be fine)" if item["confidence"] == "low" else ""
        lines += ["", f"## {n}. {_ICON[item['severity']]} {item['title']}{maybe}", "", where]
        if item["explanation"]:
            lines += ["", item["explanation"]]
        if item["fix"]:
            lines += ["", f"**Fix:** {item['fix']}"]
        lines += [
            "",
            "<details><summary>Prompt for your AI tool</summary>",
            "",
            "````text",
            item["prompt"],
            "````",
            "",
            "</details>",
        ]
    return "\n".join(lines) + "\n"
