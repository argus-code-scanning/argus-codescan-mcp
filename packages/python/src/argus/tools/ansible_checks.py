"""Built-in Ansible checks that need the whole task, not one line.

- ``ansible-secret-no-log``: a task passes a password / token to a module without
  ``no_log: true`` (on the task, its block or the play), so the value lands in the console,
  AWX/Tower job output and callback logs.
- ``ansible-debug-secret``: ``debug`` prints a variable whose name says it is a secret.
- ``ansible-get-url-no-checksum``: ``get_url`` downloads a file without ``checksum:``, so a
  changed or tampered file is installed silently.
- ``ansible-galaxy-unpinned``: roles / collections in ``requirements.yml`` without a version,
  or pinned to a branch (main, master, HEAD).

Line rules (hardcoded secrets, TLS off, remote scripts piped to a shell…) are in
argus-languages ``ansible.yaml``.
Files are parsed with a safe YAML loader, never run.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

import yaml
from argus_languages.noise import path_context

from argus.models import Finding, ScanResult, ScanType, Severity

TOOL = "argus-ansible"
_MAX_FILE = 1024 * 1024
_LINE = "__line__"

_SECRET_ARG = re.compile(
    r"(?:^|_)(?:password|passwd|pass|token|secret|api_?key|private_key|client_secret|auth_key"
    r"|passphrase|credentials?)$",
    re.I,
)
_SECRET_VAR = re.compile(
    r"(?:password|passwd|token|secret|api_?key|private_key|client_secret|credential)", re.I
)
# Option names that contain "password" but aren't secrets, and values that lock an account.
_NOT_SECRET_ARGS = frozenset(
    {"update_password", "password_lock", "generate_ssh_key", "token_type", "validate_password"}
)
_LOWER = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFO,
}
_LOCK_VALUES = frozenset({"*", "!", "!!", "!*", "x"})
_TASK_LISTS = ("tasks", "pre_tasks", "post_tasks", "handlers")
_BLOCK_KEYS = ("block", "rescue", "always")
# Keys on a task that are not the module name.
_TASK_KEYWORDS = frozenset(
    {
        "name",
        "when",
        "loop",
        "with_items",
        "with_dict",
        "with_fileglob",
        "loop_control",
        "register",
        "become",
        "become_user",
        "become_method",
        "become_flags",
        "tags",
        "vars",
        "notify",
        "listen",
        "no_log",
        "ignore_errors",
        "changed_when",
        "failed_when",
        "delegate_to",
        "delegate_facts",
        "run_once",
        "until",
        "retries",
        "delay",
        "environment",
        "args",
        "check_mode",
        "diff",
        "any_errors_fatal",
        "throttle",
        "timeout",
        "module_defaults",
        "collections",
        "connection",
        "local_action",
        "async",
        "poll",
        "ignore_unreachable",
        _LINE,
    }
)
_BRANCH_VERSIONS = frozenset({"main", "master", "head", "develop", "dev", "latest", "trunk"})
_REQUIREMENT_FILES = frozenset({"requirements.yml", "requirements.yaml"})
_SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__", ".tox"})


class _LineLoader(yaml.SafeLoader):
    """Safe loader that records each mapping's line and accepts !vault / !unsafe tags."""


def _construct_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    mapping = loader.construct_mapping(node, deep=True)
    mapping[_LINE] = node.start_mark.line + 1
    return mapping


def _construct_tagged(loader: yaml.SafeLoader, suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        return f"!{suffix} {loader.construct_scalar(node)}"
    return None


_LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)
_LineLoader.add_multi_constructor("!", _construct_tagged)


def _load(path: Path) -> Any:
    try:
        if path.stat().st_size > _MAX_FILE:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if text.lstrip().startswith("$ANSIBLE_VAULT"):
        return None  # encrypted file: nothing to see, and that's the point
    try:
        loader = _LineLoader(text)  # a SafeLoader: plain data only, no Python objects
        try:
            return loader.get_single_data()
        finally:
            loader.dispose()
    except yaml.YAMLError:
        return None


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
    cwe: str = "",
) -> Finding:
    # Tests (tests/, molecule/) and docs get the same treatment as the line rules: reported
    # one severity lower and marked, so they don't fail CI on their own.
    context = path_context(file) or ""
    if context:
        severity = _LOWER.get(severity, severity)
    return Finding(
        context=context,
        title=title,
        severity=severity,
        scan_type=ScanType.IAC,
        tool=TOOL,
        file=file,
        line=line,
        rule_id=rule,
        description=detail,
        fix_guidance=fix,
        confidence=confidence,
        cwe=cwe,
    )


def _is_true(value: Any) -> bool:
    return value is True or str(value).strip().lower() in {"true", "yes", "1", "on"}


def _module(task: dict[str, Any]) -> tuple[str, Any] | None:
    for key, value in task.items():
        if isinstance(key, str) and key not in _TASK_KEYWORDS and key not in _BLOCK_KEYS:
            return key, value
    return None


def _short(module: str) -> str:
    return module.rsplit(".", 1)[-1]


def _secret_args(module: str, args: Any) -> list[str]:
    """Argument names that carry a secret value."""
    if isinstance(args, str):
        return [m.group(1) for m in re.finditer(r"\b(\w*(?:password|token|secret))=\S", args, re.I)]
    if not isinstance(args, dict):
        return []
    found = [
        str(k)
        for k, v in args.items()
        if isinstance(k, str)
        and k not in (_LINE, *_NOT_SECRET_ARGS)
        and _SECRET_ARG.search(k)
        and v not in (None, "")
        and not isinstance(v, (bool, int))
        and str(v).strip() not in _LOCK_VALUES
    ]
    headers = args.get("headers")
    if isinstance(headers, dict) and any(
        str(k).lower() in {"authorization", "x-api-key", "private-token", "x-auth-token"}
        for k in headers
    ):
        found.append("headers")
    if _short(module) in {"uri", "get_url"} and args.get("url_password"):
        found.append("url_password")
    return sorted(set(found))


class _Checker:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.findings: list[Finding] = []

    def rel(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.name

    def tasks(self, items: Any, rel: str, inherited_no_log: bool) -> None:
        if not isinstance(items, list):
            return
        for task in items:
            if not isinstance(task, dict):
                continue
            no_log = inherited_no_log or _is_true(task.get("no_log", False))
            if any(key in task for key in _BLOCK_KEYS):
                for key in _BLOCK_KEYS:
                    self.tasks(task.get(key), rel, no_log)
                continue
            self.task(task, rel, no_log)

    def task(self, task: dict[str, Any], rel: str, no_log: bool) -> None:
        found = _module(task)
        if found is None:
            return
        module, args = found
        if isinstance(task.get("args"), dict) and not isinstance(args, dict):
            args = task["args"]
        line = int(task.get(_LINE, 0))
        short = _short(module)
        name = str(task.get("name") or short)

        secrets = _secret_args(module, args)
        if secrets and not no_log:
            self.findings.append(
                _finding(
                    "ansible-secret-no-log",
                    f'Task "{name}" passes a secret ({", ".join(secrets)}) without no_log',
                    Severity.MEDIUM,
                    rel,
                    line,
                    "Ansible prints module arguments in verbose runs, on failure and in "
                    "AWX/Tower job output, so the value ends up in logs.",
                    "Add no_log: true to the task (or its block), and keep the value in "
                    "ansible-vault.",
                    cwe="CWE-532",
                )
            )

        if short == "debug" and not no_log and isinstance(args, dict):
            shown = " ".join(str(args.get(k, "")) for k in ("var", "msg"))
            match = re.search(r"\{\{\s*([\w.]+)|^\s*([\w.]+)\s*$", shown)
            variable = match.group(1) or match.group(2) if match else ""
            if variable and _SECRET_VAR.search(variable):
                self.findings.append(
                    _finding(
                        "ansible-debug-secret",
                        f"debug prints {variable}, which looks like a secret",
                        Severity.MEDIUM,
                        rel,
                        line,
                        "The value is printed to the console and stored in job logs.",
                        "Remove the debug task, or print only that the value is set "
                        "(msg: \"{{ 'set' if db_password is defined else 'missing' }}\").",
                        cwe="CWE-532",
                    )
                )

        if short == "get_url" and isinstance(args, dict) and not args.get("checksum"):
            url = str(args.get("url", ""))
            if url and not re.search(r"\.(?:asc|sig|sha256|sha512)$", url):
                self.findings.append(
                    _finding(
                        "ansible-get-url-no-checksum",
                        "File downloaded without a checksum",
                        Severity.LOW,
                        rel,
                        line,
                        "Without checksum:, a changed or tampered download is installed "
                        "without any error.",
                        'Add checksum: "sha256:<hash>" (or sha256:<url of the checksum file>).',
                        confidence="medium",
                        cwe="CWE-494",
                    )
                )

    def playbook(self, data: Any, rel: str) -> None:
        if not isinstance(data, list):
            return
        if all(
            isinstance(item, dict) and _module(item) for item in data if isinstance(item, dict)
        ) and not any(
            isinstance(item, dict) and ("hosts" in item or "import_playbook" in item)
            for item in data
        ):
            self.tasks(data, rel, False)  # a role's tasks/ or handlers/ file
            return
        for play in data:
            if not isinstance(play, dict):
                continue
            no_log = _is_true(play.get("no_log", False))
            for key in _TASK_LISTS:
                self.tasks(play.get(key), rel, no_log)

    def requirements(self, data: Any, rel: str) -> None:
        entries: list[tuple[str, Any]] = []
        if isinstance(data, list):
            entries = [("role", item) for item in data]
        elif isinstance(data, dict):
            entries = [("role", item) for item in data.get("roles") or []]
            entries += [("collection", item) for item in data.get("collections") or []]
        for kind, item in entries:
            if isinstance(item, str):
                name, version, src, line = item, None, item, 0
            elif isinstance(item, dict):
                name = str(item.get("name") or item.get("src") or "?")
                version, src = item.get("version"), str(item.get("src", ""))
                line = int(item.get(_LINE, 0))
            else:
                continue
            from_git = src.startswith(("git+", "git@", "https://github", "http")) or src.endswith(
                ".git"
            )
            branch = version is not None and str(version).strip().lower() in _BRANCH_VERSIONS
            if version is None or branch:
                what = f"pinned to the branch {version}" if branch else "has no version"
                self.findings.append(
                    _finding(
                        "ansible-galaxy-unpinned",
                        f"Galaxy {kind} {name} {what}",
                        Severity.MEDIUM if from_git or branch else Severity.LOW,
                        rel,
                        line,
                        "Every run installs whatever is newest, so a compromised or broken "
                        "release reaches your servers without a review.",
                        "Pin an exact version (version: 2.4.1, or a commit SHA for git sources) "
                        "and update it on purpose.",
                        cwe="CWE-1357",
                    )
                )


def _candidate_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    out: list[Path] = []
    for path in root.rglob("*"):
        if path.suffix in {".yml", ".yaml"} and not any(p in _SKIP_DIRS for p in path.parts):
            out.append(path)
    return sorted(out)


def _looks_like_playbook(rel: str, data: Any) -> bool:
    lower = f"/{rel.lower()}"
    if any(m in lower for m in ("/tasks/", "/handlers/", "/playbooks/", "/roles/")):
        return True
    return isinstance(data, list) and any(
        isinstance(item, dict) and ("hosts" in item or "import_playbook" in item) for item in data
    )


def ansible_findings(target: str) -> tuple[list[Finding], dict[str, object]]:
    path = Path(target)
    root = path if path.is_dir() else path.parent
    checker = _Checker(root)
    scanned = 0
    for file in _candidate_files(path):
        rel = checker.rel(file)
        if file.name in _REQUIREMENT_FILES:
            data = _load(file)
            if data is not None:
                scanned += 1
                checker.requirements(data, rel)
            continue
        if re.search(
            r"(?:^|/)(?:\.github|\.gitlab|docker-compose|compose|k8s|kubernetes|charts|helm)", rel
        ):
            continue
        data = _load(file)
        if data is not None and _looks_like_playbook(rel, data):
            scanned += 1
            checker.playbook(data, rel)
    return checker.findings, {"ansible_files": scanned}


async def run_ansible_checks(target: str) -> ScanResult:
    result = ScanResult(tool=TOOL, scan_type=ScanType.IAC, target=target)
    try:
        findings, metadata = await asyncio.to_thread(ansible_findings, target)
    except Exception as exc:  # never break a scan
        result.errors.append(f"argus-ansible error: {exc}")
        return result
    result.findings.extend(findings)
    result.metadata.update(metadata)
    return result
