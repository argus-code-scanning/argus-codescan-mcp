"""Deterministic fixes for GitHub Actions workflow findings.

Two Opengrep/Semgrep registry rules:

- ``github-actions-mutable-action-tag``: pin ``uses: owner/repo@v4`` to the commit the tag
  points at today (``@<sha> # v4``), so the action owner can't silently repoint it.
- ``run-shell-injection``: move ``${{ github.* }}`` out of a ``run:`` script into the step's
  ``env:``, so attacker-controlled text (PR titles, branch names) is data, not shell code.

Both edit only the lines they need and refuse when the result isn't valid YAML.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import yaml

from argus.utils import is_tool_available, run_command

PIN_RULE = "github-actions-mutable-action-tag"
INJECTION_RULE = "run-shell-injection"

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# uses: owner/repo[/path]@ref   (optional quotes, optional trailing comment)
USES_RE = re.compile(
    r"""^(?P<head>\s*(?:-\s+)?uses:\s*)(?P<q>['"]?)(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)"""
    r"""@(?P<ref>[A-Za-z0-9_./-]+)(?P=q)(?P<tail>\s*(?:#.*)?)$"""
)
OWNER_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GITHUB_EXPR_RE = re.compile(r"\$\{\{\s*(github\.[A-Za-z0-9_.\-\[\]'\"*]+)\s*\}\}")
POSIX_SHELLS = {"", "bash", "sh"}

Resolver = Callable[[str, str], Awaitable[str | None]]


@dataclass
class FixOutcome:
    ok: bool
    message: str
    text: str = ""


def handles(rule_id: str) -> bool:
    """True when ``rule_id`` is one of the GitHub Actions rules fixed here."""
    rid = rule_id.strip().lower()
    return rid.endswith(PIN_RULE) or rid.endswith(INJECTION_RULE)


async def resolve_ref(action: str, ref: str) -> str | None:
    """Commit SHA for ``ref`` (tag or branch) of github.com/<owner>/<repo>, via git ls-remote."""
    owner_repo = "/".join(action.split("/")[:2])
    if not OWNER_REPO_RE.match(owner_repo) or not is_tool_available("git"):
        return None
    url = f"https://github.com/{owner_repo}.git"
    refs = [f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}", f"refs/heads/{ref}"]
    code, stdout, _ = await run_command(["git", "ls-remote", url, *refs], timeout=30)
    if code != 0:
        return None
    found: dict[str, str] = {}
    for row in stdout.splitlines():
        parts = row.split()
        if len(parts) == 2 and SHA_RE.match(parts[0]):
            found[parts[1]] = parts[0]
    # Annotated tags: the peeled ^{} entry is the commit; the plain entry is the tag object.
    for key in (f"refs/tags/{ref}^{{}}", f"refs/tags/{ref}", f"refs/heads/{ref}"):
        if key in found:
            return found[key]
    return None


async def pin_action(text: str, line: int, resolver: Resolver = resolve_ref) -> FixOutcome:
    """Pin the ``uses:`` on ``line`` (1-based) to a commit SHA."""
    lines = text.splitlines(keepends=True)
    if not 1 <= line <= len(lines):
        return FixOutcome(False, f"Line {line} is outside the file.")
    raw = lines[line - 1]
    body = raw.rstrip("\r\n")
    newline = raw[len(body) :]
    match = USES_RE.match(body)
    if not match:
        return FixOutcome(False, f"No 'uses: owner/repo@ref' on line {line}.")
    action, ref = match["action"], match["ref"]
    if SHA_RE.match(ref):
        return FixOutcome(False, "This action is already pinned to a commit SHA.")
    sha = await resolver(action, ref)
    if not sha or not SHA_RE.match(sha):
        return FixOutcome(
            False,
            f"Could not resolve {action}@{ref} to a commit (network, private repo or unknown ref). "
            "Pin it manually: find the commit for the tag on GitHub and use @<sha> # <tag>.",
        )
    q = match["q"]
    lines[line - 1] = f"{match['head']}{q}{action}@{sha}{q} # {ref}{newline}"
    return FixOutcome(True, f"Pinned {action}@{ref} to {sha}.", "".join(lines))


def _indent(s: str) -> int:
    return len(s) - len(s.lstrip(" "))


def _env_name(expr: str, taken: set[str]) -> str:
    parts = [
        re.sub(r"[^A-Za-z0-9_]+", "_", p).strip("_")
        for p in expr.split(".")
        if p and p.lower() != "github"
    ]
    parts = [p for p in parts if p]
    if parts and parts[0].lower() == "event":
        parts = parts[1:]
    base = "_".join(parts[-2:]).upper() or "GITHUB_VALUE"
    if base[0].isdigit():
        base = f"V_{base}"
    name, n = base, 2
    while name in taken:
        name, n = f"{base}_{n}", n + 1
    taken.add(name)
    return name


def _replace_in_line(line: str, mapping: dict[str, str], taken: set[str]) -> str:
    """Replace ${{ github.x }} with a shell variable, quoted for where it sits on the line."""
    out: list[str] = []
    in_single = in_double = False
    i = 0
    while i < len(line):
        m = GITHUB_EXPR_RE.match(line, i)
        if m:
            expr = m.group(1)
            if expr not in mapping:
                mapping[expr] = _env_name(expr, taken)
            var = mapping[expr]
            if in_double:
                out.append(f"${{{var}}}")
            elif in_single:
                out.append(f"'\"${{{var}}}\"'")  # close ', insert "$VAR", reopen '
            else:
                out.append(f'"${{{var}}}"')
            i = m.end()
            continue
        ch = line[i]
        if ch == "\\" and not in_single and i + 1 < len(line):
            out.append(line[i : i + 2])
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        out.append(ch)
        i += 1
    return "".join(out)


def fix_run_injection(text: str, line: int) -> FixOutcome:
    """Move ``${{ github.* }}`` out of the ``run:`` script around ``line`` into ``env:``."""
    lines = text.splitlines(keepends=True)
    if not 1 <= line <= len(lines):
        return FixOutcome(False, f"Line {line} is outside the file.")

    # Find the run: key at or above the reported line.
    run_idx = None
    for idx in range(line - 1, -1, -1):
        if re.match(r"^\s*(?:-\s+)?run:", lines[idx]):
            run_idx = idx
            break
    if run_idx is None:
        return FixOutcome(False, f"No 'run:' step found at or above line {line}.")

    run_line = lines[run_idx]
    dash = re.match(r"^(\s*)-\s+", run_line)
    key_indent = len(dash.group(0)) if dash else _indent(run_line)

    # Step boundaries: the '- ' item that owns this run: key, and the next sibling/parent.
    start = run_idx
    if not dash:
        for idx in range(run_idx - 1, -1, -1):
            s = lines[idx]
            if not s.strip() or s.lstrip().startswith("#"):
                continue
            if re.match(rf"^\s{{{key_indent - 2}}}-\s+", s) and _indent(s) == key_indent - 2:
                start = idx
                break
            if _indent(s) < key_indent:
                return FixOutcome(False, "Could not find the step that owns this run: script.")
    end = len(lines)
    for idx in range(run_idx + 1, len(lines)):
        s = lines[idx]
        if s.strip() and not s.lstrip().startswith("#") and _indent(s) < key_indent:
            end = idx
            break

    # The step's shell must be POSIX for "$VAR" references.
    for idx in range(start, end):
        m = re.match(rf"^(?:\s*-\s+|\s{{{key_indent}}})shell:\s*(\S+)", lines[idx])
        if m and m.group(1).strip("'\"").split()[0] not in POSIX_SHELLS:
            return FixOutcome(
                False,
                f"Step uses shell '{m.group(1)}': only bash/sh steps are fixed automatically. "
                "Move the ${{ }} value into env: and read it with that shell's syntax.",
            )

    # Script lines: the run: line's inline value plus deeper-indented block lines.
    run_end = run_idx + 1
    while run_end < end:
        s = lines[run_end]
        if s.strip() and _indent(s) <= key_indent:
            break
        run_end += 1

    # Existing env: keys on this step.
    env_idx = None
    taken: set[str] = set()
    for idx in range(start, end):
        if re.match(rf"^(?:\s*-\s+|\s{{{key_indent}}})env:\s*$", lines[idx]):
            env_idx = idx
            for j in range(idx + 1, end):
                s = lines[j]
                if s.strip() and _indent(s) <= key_indent:
                    break
                km = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:", s)
                if km:
                    taken.add(km.group(1))
            break

    mapping: dict[str, str] = {}
    new_lines = list(lines)
    for idx in range(run_idx, run_end):
        new_lines[idx] = _replace_in_line(lines[idx], mapping, taken)
    if not mapping:
        return FixOutcome(False, "No ${{ github.* }} expressions found in this run: script.")

    pad = " " * key_indent
    entries = [f"{pad}  {name}: ${{{{ {expr} }}}}\n" for expr, name in mapping.items()]
    if env_idx is not None:
        insert_at = env_idx + 1
        while insert_at < end:
            s = new_lines[insert_at]
            if s.strip() and _indent(s) <= key_indent:
                break
            insert_at += 1
        new_lines[insert_at:insert_at] = entries
    else:
        if not new_lines[run_end - 1].endswith("\n"):
            new_lines[run_end - 1] += "\n"
        new_lines[run_end:run_end] = [f"{pad}env:\n", *entries]

    fixed = "".join(new_lines)
    try:
        before, after = yaml.safe_load(text), yaml.safe_load(fixed)
    except yaml.YAMLError as exc:
        return FixOutcome(False, f"Refusing: the fixed workflow would not be valid YAML ({exc}).")
    if type(before) is not type(after):
        return FixOutcome(False, "Refusing: the fix changed the workflow's structure.")
    names = ", ".join(f"{n} ← {e}" for e, n in mapping.items())
    return FixOutcome(True, f"Moved {len(mapping)} expression(s) into env: ({names}).", fixed)


async def fix_github_actions(
    text: str, rule_id: str, line: int, resolver: Resolver = resolve_ref
) -> FixOutcome:
    rid = rule_id.strip().lower()
    if rid.endswith(PIN_RULE):
        return await pin_action(text, line, resolver)
    if rid.endswith(INJECTION_RULE):
        return fix_run_injection(text, line)
    return FixOutcome(False, f"No GitHub Actions fix for rule {rule_id}.")
