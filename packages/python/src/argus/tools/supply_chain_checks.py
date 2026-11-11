"""Worm-style supply-chain malware checks that need a whole file or a parsed manifest.

- #134 npm install hooks (preinstall / install / postinstall / prepare / prepublish) that
  download and run code, run inline code, or decode payloads
- #135 credential harvesting: several credential stores read in one file that also talks to
  the network (the ChainDrop / Shai-Hulud / s1ngularity stealer pattern)
- #136 self-propagation: package code that publishes packages or enumerates a maintainer's
  packages on the npm registry

Everything here is static: files are read, never executed. Release tooling (`.github/`,
paths named release*/publish*) is allowed to publish and to read registry tokens, so the
#135 and #136 checks skip it.

Some regexes below write a literal with a character class (``\\.npm[r]c``) so that this
module's own source does not match the patterns it defines.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

from argus_languages.discover import discover_files

from argus.models import Finding, ScanType, Severity

TOOL = "argus-malware"
_CODE_LANGUAGES = frozenset({"javascript", "typescript", "python", "shell"})
_GENERATED_NAME = re.compile(r"\.(?:min|bundle|chunk)\.[cm]?js$", re.IGNORECASE)
_SKIP_DIRS = frozenset(
    {"node_modules", ".git", ".venv", "venv", "dist", "build", ".next", "coverage", "vendor"}
)


def _finding(
    relative: str,
    line: int,
    rule_id: str,
    title: str,
    severity: Severity,
    detail: str,
    fix: str,
    confidence: str = "medium",
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        scan_type=ScanType.MALWARE,
        tool=TOOL,
        file=relative,
        line=line,
        rule_id=rule_id,
        description=detail,
        fix_guidance=fix,
        confidence=confidence,
    )


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, max(index, 0)) + 1


def is_release_tooling(relative: str) -> bool:
    """CI workflows and release/publish scripts are expected to publish and read tokens."""
    parts = [p.lower() for p in PurePosixPath(relative).parts]
    if any(p in {".github", ".changeset", ".circleci", ".gitlab-ci"} for p in parts):
        return True
    return any(re.match(r"(?:release|publish)", p) for p in parts)


# ── #134 npm lifecycle scripts ────────────────────────────────────────────────

LIFECYCLE_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish")

_DOWNLOAD = r"(?:\bcurl\b|\bwget\b|Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\birm\b)"
_DOWNLOAD_AND_RUN = re.compile(
    _DOWNLOAD
    + r"[^|;&]*\|\s*(?:sudo\s+)?(?:(?:ba|z|da)?sh|node|python3?|perl|ruby|iex|Invoke-Expression)\b"
    + r"|"
    + _DOWNLOAD
    + r".*?(?:&&|;)\s*(?:chmod\s+\+x|\./|(?:ba)?sh\s|node\s|python3?\s)",
    re.IGNORECASE,
)
_INLINE_CODE = re.compile(
    r"\bnode\s+(?:-e|--eval|-p|--print)\b|\bpython3?\s+-c\b|\b(?:perl|ruby)\s+-e\b"
    r"|(?:^|[;&|]\s*)eval\s|\beval\s*\(|(?:^|[;&|]\s*)iex\b|Invoke-Expression",
    re.IGNORECASE,
)
_ENCODED = re.compile(
    r"base64\s+(?:-d|--decode)|Buffer\.from\([^)]*base64|\batob\s*\(|FromBase64String"
    r"|[A-Za-z0-9+/]{60,}={0,2}"
)
_RUNS_FILE = re.compile(
    r"(?:^|&&|;|\|\|)\s*(?:(?:node|sh|bash|python3?)\s+(?!-)[\w./@-]+\.(?:c?js|mjs|sh|py)\b|\./\S+)"
)
# Common install-time tools that are fine on their own.
_SAFE_SEGMENT = re.compile(
    r"^(?:husky(?:\s+install)?|patch-package\b.*|node-gyp(?:-build)?(?:\s+rebuild)?"
    r"|prebuild-install\b.*|prisma\s+generate\b.*|tsc\b.*|esbuild\b.*|ngcc\b.*"
    r"|electron-builder\s+install-app-deps|simple-git-hooks|lefthook\s+install"
    r"|svelte-kit\s+sync|nuxi?\s+prepare|playwright\s+install\b.*|cypress\s+install"
    r"|lerna\s+bootstrap|is-ci\b.*|echo\b.*|exit\s+0|true|rimraf\b.*)$"
)
_RUN_SCRIPT = re.compile(r"^(?:npm|pnpm|yarn)\s+(?:run\s+)?([\w:.-]+)$")


def _lifecycle_verdict(command: str) -> tuple[str, Severity, str, str] | None:
    """(rule id, severity, confidence, what it does) for one install-hook command."""
    if _DOWNLOAD_AND_RUN.search(command):
        return "malware-npm-install-download-exec", Severity.HIGH, "high", "downloads and runs code"
    if _ENCODED.search(command):
        return "malware-npm-install-encoded", Severity.HIGH, "high", "decodes an encoded payload"
    if _INLINE_CODE.search(command):
        return "malware-npm-install-inline-code", Severity.HIGH, "medium", "runs inline code"
    if re.search(_DOWNLOAD, command, re.IGNORECASE):
        return "malware-npm-install-downloads", Severity.MEDIUM, "low", "downloads from the network"
    segments = [s.strip() for s in re.split(r"&&|\|\||;", command) if s.strip()]
    if all(_SAFE_SEGMENT.match(s) or _RUN_SCRIPT.match(s) for s in segments):
        return None
    if _RUNS_FILE.search(command):
        return (
            "malware-npm-install-runs-file",
            Severity.MEDIUM,
            "low",
            "runs a file at install time",
        )
    return None


def _expand(command: str, scripts: dict[str, object], depth: int = 0) -> str:
    """Inline `npm run x` targets one or two levels deep, so a hook can't hide behind them."""
    if depth > 2:
        return command
    parts = []
    for segment in re.split(r"(&&|\|\||;)", command):
        match = _RUN_SCRIPT.match(segment.strip())
        target = scripts.get(match.group(1)) if match else None
        if isinstance(target, str) and match and match.group(1) not in LIFECYCLE_HOOKS:
            parts.append(_expand(target, scripts, depth + 1))
        else:
            parts.append(segment)
    return "".join(parts)


def lifecycle_script_findings(text: str, relative: str) -> list[Finding]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return []
    findings = []
    for hook in LIFECYCLE_HOOKS:
        command = scripts.get(hook)
        if not isinstance(command, str) or not command.strip():
            continue
        verdict = _lifecycle_verdict(_expand(command, scripts))
        if verdict is None:
            continue
        rule_id, severity, confidence, what = verdict
        shown = command if len(command) <= 120 else command[:117] + "..."
        findings.append(
            _finding(
                relative,
                _line_of(text, text.find(f'"{hook}"')),
                rule_id,
                f"npm {hook} script {what}: {shown}",
                severity,
                f'`npm install` runs the "{hook}" script automatically on every machine and CI '
                "runner that installs this package. Worms (Shai-Hulud, ChainDrop) spread this way.",
                "Remove the install hook or replace it with an explicit, documented build step. "
                "If you did not add it, treat the package as compromised: unpublish the affected "
                "versions and rotate npm, GitHub and cloud tokens.",
                confidence,
            )
        )
    return findings


def iter_package_json(target: Path, max_depth: int = 8) -> Iterator[Path]:
    if target.is_file():
        if target.name == "package.json":
            yield target
        return

    def walk(directory: Path, depth: int) -> Iterator[Path]:
        if depth > max_depth:
            return
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            return
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in _SKIP_DIRS:
                    yield from walk(entry, depth + 1)
            elif entry.name == "package.json":
                yield entry

    yield from walk(target, 0)


# ── #135 credential harvesting ────────────────────────────────────────────────

# Credential stores a stealer reads. "machine" stores are rarely touched by ordinary code.
_CREDENTIAL_SOURCES: dict[str, tuple[re.Pattern[str], bool]] = {
    "npm token": (re.compile(r"\.npm[r]c\b|\bNPM_TOKE[N]\b|\bNODE_AUTH_TOKE[N]\b"), False),
    "PyPI token": (
        re.compile(r"\.pypir[c]\b|\bTWINE_PASSWOR[D]\b|\bPYPI_(?:API_)?TOKE[N]\b"),
        False,
    ),
    "GitHub token": (
        re.compile(r"\bGITHUB_TOKE[N]\b|\bGH_TOKE[N]\b|\bACTIONS_(?:RUNTIME|ID_TOKEN_REQUEST)_\w+"),
        False,
    ),
    "cloud metadata": (
        re.compile(r"169\.254\.169\.25[4]|169\.254\.170\.[2]\b|metadata\.google\.interna[l]"),
        True,
    ),
    "Vault token": (re.compile(r"\bVAULT_TOKE[N]\b|\.vault-toke[n]"), True),
    "Kubernetes credentials": (
        re.compile(r"\.kube/confi[g]|/var/run/secrets/kubernetes\.i[o]|\bKUBECONFI[G]\b"),
        True,
    ),
    "AWS credentials": (
        re.compile(r"\.aws/credential[s]|\bAWS_SECRET_ACCESS_KE[Y]\b|\bAWS_SESSION_TOKE[N]\b"),
        True,
    ),
    "GCP credentials": (
        re.compile(r"application_default_credentials\.jso[n]|\bGOOGLE_APPLICATION_CREDENTIAL[S]\b"),
        True,
    ),
    "SSH keys": (re.compile(r"\.ssh/id_(?:rs[a]|ed2551[9]|ecds[a]|ds[a])"), True),
    "Docker credentials": (re.compile(r"\.docker/config\.jso[n]"), True),
    "crypto wallets": (
        re.compile(r"wallet\.da[t]\b|exodus\.walle[t]|\.electru[m]/|/keystore/UTC--"),
        True,
    ),
}
_NETWORK_SINK = re.compile(
    r"\bfetch\s*\(|\baxios\b|\bhttps?\.(?:request|get)\s*\(|\brequests\.(?:post|put|get)\s*\("
    r"|\burllib\.request\b|\bXMLHttpRequest\b|\bnew\s+WebSocket\b|\bsocket\.connect\b"
    r"|\bdns\.resolve|\bcurl\s|\bwget\s|\bgit\s+push\b|\bgh\s+repo\s+create\b|webhook"
)


def credential_harvest_findings(text: str, relative: str) -> list[Finding]:
    if is_release_tooling(relative):
        return []
    hits: dict[str, int] = {}
    for label, (pattern, _machine) in _CREDENTIAL_SOURCES.items():
        match = pattern.search(text)
        if match:
            hits[label] = match.start()
    machine = [label for label in hits if _CREDENTIAL_SOURCES[label][1]]
    # Release scripts read npm + GitHub tokens; a stealer goes after machine credentials too.
    if not (len(hits) >= 3 or (len(hits) >= 2 and machine)):
        return []
    sink = _NETWORK_SINK.search(text)
    if not sink:
        return []
    sources = ", ".join(sorted(hits))
    return [
        _finding(
            relative,
            _line_of(text, min(hits.values())),
            "malware-credential-harvesting",
            f"Reads several credential stores and sends data over the network ({sources})",
            Severity.HIGH,
            f"This file reads {len(hits)} kinds of credentials ({sources}) and also makes a "
            "network call. That is the signature of the worm stealers (ChainDrop, Shai-Hulud, "
            "s1ngularity) that collect every token on a machine and send them out.",
            "Check who added this code and what it sends. If it is not yours, treat every "
            "machine and CI runner that ran it as compromised and rotate all listed credentials.",
            "high",
        )
    ]


# ── #136 self-propagation ─────────────────────────────────────────────────────

_EXEC_CALL = r"(?:\bexec(?:Sync|File|FileSync)?|\bspawn(?:Sync)?|\bexeca(?:Sync)?|subprocess\.\w+|os\.system|os\.popen)\s*\("
_PUBLISH_CMD = (
    r"(?:\b(?:npm|pnpm|yarn)[\"'`,\s\[]+publish\b|\btwine[\"'`,\s\[]+upload\b"
    r"|\bgem[\"'`,\s\[]+push\b|-m[\"'`,\s]+twine\b)"
)
_PUBLISH_FROM_CODE = re.compile(_EXEC_CALL + r"[^\n]{0,200}?" + _PUBLISH_CMD)
_REGISTRY_ENUMERATION = re.compile(
    r"registry\.npmjs\.org/-/(?:v1/search\?[^\s\"'`]*maintainer|user/[^\s\"'`]+/package|org/)"
    r"|[?&]text=maintainer(?::|%3A)"
)


def self_propagation_findings(text: str, relative: str) -> list[Finding]:
    if is_release_tooling(relative):
        return []
    findings = []
    publish = _PUBLISH_FROM_CODE.search(text)
    if publish:
        findings.append(
            _finding(
                relative,
                _line_of(text, publish.start()),
                "malware-publish-from-code",
                "Package code publishes packages (npm publish / twine upload / gem push)",
                Severity.HIGH,
                "Library and app code never needs to publish packages. Worms (Shai-Hulud, "
                "ChainDrop) use a stolen token to publish infected versions of the victim's "
                "other packages this way.",
                "Move publishing to release tooling (CI workflow, scripts/release*). If you did "
                "not write this, treat the package as compromised and revoke registry tokens.",
                "high",
            )
        )
    enumeration = _REGISTRY_ENUMERATION.search(text)
    if enumeration:
        findings.append(
            _finding(
                relative,
                _line_of(text, enumeration.start()),
                "malware-npm-maintainer-enumeration",
                "Code lists a maintainer's packages on the npm registry",
                Severity.HIGH,
                "Querying the registry for a maintainer's packages is how npm worms pick the "
                "next packages to infect.",
                "Remove the lookup unless this is a registry tool you maintain on purpose.",
            )
        )
    return findings


# ── entry point ───────────────────────────────────────────────────────────────


def run_supply_chain_checks(target: str) -> list[Finding]:
    root = Path(target)
    base = root if root.is_dir() else root.parent
    findings: list[Finding] = []
    for manifest in iter_package_json(root):
        try:
            text = manifest.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(lifecycle_script_findings(text, manifest.relative_to(base).as_posix()))
    for scanned in discover_files(root):
        if scanned.language not in _CODE_LANGUAGES or _GENERATED_NAME.search(scanned.path.name):
            continue
        try:
            text = scanned.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(credential_harvest_findings(text, scanned.relative))
        findings.extend(self_propagation_findings(text, scanned.relative))
    return findings
