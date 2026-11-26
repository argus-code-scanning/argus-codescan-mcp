"""Project-level checks for apps built mostly with AI tools (#272).

The failures that leak most data in AI-built apps aren't on one line:

- Supabase tables created without Row Level Security (anyone with the anon key that ships
  in the app can read and change them)
- Firebase / Firestore / Storage rules open to everyone, or still in time-limited test mode
- the Supabase service_role key used in browser code
- secrets in public env variables in .env files (NEXT_PUBLIC_, VITE_, …)
- API routes, server actions and Python endpoints that change data with no auth check

Each check only runs when the project uses that stack. Values of secrets are never printed.
Files are read, never run.
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from argus_languages.noise import path_context
from argus_languages.rules_loader import load_rules_from_files

from argus.models import Finding, ScanResult, ScanType, Severity

TOOL = "argus-vibe"
_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".next",
        "dist",
        "build",
        "out",
        ".vercel",
        ".turbo",
        "coverage",
        ".venv",
        "venv",
        "__pycache__",
        ".svelte-kit",
        ".nuxt",
        ".expo",
        "vendor",
    }
)
_MAX_FILE = 1024 * 1024
_CODE_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".py")

# --- patterns ------------------------------------------------------------------------------

_CREATE_TABLE = re.compile(
    r"\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?:\"?(\w+)\"?\.)?\"?(\w+)\"?", re.I
)
_ENABLE_RLS = re.compile(
    r"\balter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?(?:\"?(\w+)\"?\.)?\"?(\w+)\"?\s+"
    r"enable\s+row\s+level\s+security",
    re.I,
)
# do $$ ... for t in select tablename from pg_tables where schemaname = 'public' loop
#   execute format('alter table public.%I enable row level security', t);
# covers every public table created before it.
_ENABLE_RLS_LOOP = re.compile(
    r"\b(?:pg_tables|information_schema\.tables)\b[\s\S]{0,400}?"
    r"format\(\s*'[^']*enable\s+row\s+level\s+security",
    re.I,
)
_FIRESTORE_OPEN = re.compile(
    r"\ballow\s+(?:read|write|get|list|create|update|delete)(?:\s*,\s*(?:read|write|get|list|create|update|delete))*\s*(?::\s*if\s+true\s*)?;",
    re.I,
)
_FIRESTORE_TEST_MODE = re.compile(r"request\.time\s*<\s*timestamp\.date\(")
_RTDB_OPEN = re.compile(r"\"\.(?:read|write)\"\s*:\s*(?:true|\"true\")")
_SERVICE_ROLE_REF = re.compile(r"service_?role|SERVICE_ROLE", re.I)
_USE_CLIENT = re.compile(r"^\s*['\"]use client['\"]", re.M)
_USE_SERVER = re.compile(r"^\s*['\"]use server['\"]", re.M)
_ROUTE_MUTATION = re.compile(
    r"export\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b|export\s+const\s+(POST|PUT|PATCH|DELETE)\s*="
)
_SERVER_ACTION = re.compile(r"export\s+(?:default\s+)?async\s+function\s+(\w*)")
_DATA_CHANGE = re.compile(
    r"\.(?:insert|upsert|update|delete|remove)\s*\("
    r"|\bprisma\.\w+\.(?:create|createMany|update|updateMany|upsert|delete|deleteMany)\s*\("
    r"|\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b"
    r"|\b(?:setDoc|addDoc|updateDoc|deleteDoc)\s*\(|\.save\s*\(",
    re.I,
)
_AUTH_EVIDENCE = re.compile(
    r"\bauth\(\)|getServerSession|currentUser\s*\(|\bgetUser\s*\(|getSession\s*\(|getAuth\s*\("
    r"|clerkClient|requireAuth|requireUser|withAuth|verifyToken|jwt\.verify|jwtVerify|getToken\s*\("
    r"|validateRequest|isAuthenticated|session\??\.user|auth\.getUser|authenticate\s*\(|checkAuth"
    r"|ensureAuth|protectedProcedure|constructEvent|verifySignature|verifyWebhook|unauthorized"
    r"|\b401\b|[\"']authorization[\"']|getKindeServerSession|lucia|currentUserId|userId\s*=\s*await"
    # Python
    r"|Depends\(\s*(?:get_current_user|current_user|get_user|auth|verify|require|oauth2_scheme)"
    r"|login_required|jwt_required|requires_auth|current_user|HTTPBearer|OAuth2PasswordBearer"
    r"|Security\(|IsAuthenticated|permission_classes",
    re.I,
)
_MIDDLEWARE_AUTH = re.compile(
    r"clerkMiddleware|authMiddleware|withAuth|NextAuth|auth\(|getToken\(|updateSession|createServerClient|kindeMiddleware",
)
_PY_MUTATION_ROUTE = re.compile(
    r"@\w+\.(?:post|put|patch|delete)\s*\(|@\w+\.route\([^)]*methods\s*=\s*\[[^\]]*['\"](?:POST|PUT|PATCH|DELETE)['\"]",
)
_PY_DATA_CHANGE = re.compile(
    r"\.(?:add|commit|delete|insert|update|upsert|save|create)\s*\(|\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b",
    re.I,
)


@dataclass
class Project:
    root: Path
    files: list[Path] = field(default_factory=list)
    package_json: str = ""
    supabase: bool = False
    firebase: bool = False
    vite: bool = False
    middleware_auth: str | None = None


def _rel(project: Project, path: Path) -> str:
    return path.relative_to(project.root).as_posix() if path != project.root else path.name


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > _MAX_FILE:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def discover(root: Path) -> Project:
    base = root if root.is_dir() else root.parent
    project = Project(root=base)
    if root.is_file():
        project.files = [root]
    else:
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            project.files.extend(Path(dirpath) / f for f in filenames)
    for path in project.files:
        name = path.name
        if name == "package.json" and "node_modules" not in path.parts and not project.package_json:
            project.package_json = _read(path)
        if name.startswith("vite.config."):
            project.vite = True
        if name in {"firebase.json", "firestore.rules", "storage.rules", "database.rules.json"}:
            project.firebase = True
        if name == "config.toml" and path.parent.name == "supabase":
            project.supabase = True
        if name in {"middleware.ts", "middleware.js"} and project.middleware_auth is None:
            text = _read(path)
            if _MIDDLEWARE_AUTH.search(text):
                project.middleware_auth = _rel(project, path)
    pkg = project.package_json
    project.supabase = (
        project.supabase
        or "@supabase/" in pkg
        or any("supabase" in p.parts and p.suffix == ".sql" for p in project.files)
    )
    project.vite = project.vite or '"vite"' in pkg
    project.firebase = project.firebase or '"firebase"' in pkg or '"firebase-admin"' in pkg
    return project


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
    cwe: str = "CWE-284",
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
        cwe=cwe,
    )


# --- checks --------------------------------------------------------------------------------


def check_env_files(project: Project) -> list[Finding]:
    rule = next(
        (r for r in load_rules_from_files(("vibe.yaml",)) if r.id == "vibe-public-env-secret"), None
    )
    if rule is None:
        return []
    out: list[Finding] = []
    for path in project.files:
        name = path.name
        if not (name == ".env" or name.startswith(".env.")) or name.endswith(
            (".example", ".sample", ".template", ".dist")
        ):
            continue
        for number, line in enumerate(_read(path).splitlines(), start=1):
            m = re.match(r"\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(.*)", line)
            if not m or not m.group(2).strip().strip("'\""):
                continue
            if rule.pattern.fullmatch(m.group(1)):
                out.append(
                    _finding(
                        "vibe-public-env-secret",
                        f"{m.group(1)} is a secret in a public env variable — it's bundled into the website",
                        Severity.HIGH,
                        _rel(project, path),
                        number,
                        f"Variables with this prefix are copied into the JavaScript every visitor "
                        f"downloads, so {m.group(1)} can be read in the browser's dev tools.",
                        rule.fix_guidance,
                        cwe="CWE-200",
                    )
                )
    return out


def check_supabase_rls(project: Project) -> list[Finding]:
    if not project.supabase:
        return []
    created: dict[str, tuple[str, int]] = {}
    enabled: set[str] = set()
    # Migrations run in file-name order; a loop over pg_tables only covers tables made before it.
    for path in sorted(project.files, key=lambda p: _rel(project, p)):
        if path.suffix.lower() != ".sql" or path_context(_rel(project, path)) == "test":
            continue
        text = _read(path)
        loops = [m.start() for m in _ENABLE_RLS_LOOP.finditer(text)]
        here: list[tuple[str, int]] = []
        for m in _CREATE_TABLE.finditer(text):
            schema = (m.group(1) or "public").lower()
            if schema == "public":
                table = m.group(2).lower()
                created.setdefault(table, (_rel(project, path), _line_of(text, m.start())))
                here.append((table, m.start()))
        if loops:
            last = loops[-1]
            enabled.update(t for t in created if t not in dict(here))
            enabled.update(t for t, pos in here if pos < last)
        for m in _ENABLE_RLS.finditer(text):
            if (m.group(1) or "public").lower() == "public":
                enabled.add(m.group(2).lower())
    return [
        _finding(
            "vibe-supabase-table-without-rls",
            f"Table {table} has no Row Level Security — anyone with your public key can read and change it",
            Severity.HIGH,
            file,
            line,
            "Supabase tables in the public schema are reachable with the anon key that ships in "
            "your app. Without RLS, that key can read, change and delete every row.",
            f"alter table public.{table} enable row level security; then add policies for who may "
            "read and write, e.g. using (auth.uid() = user_id).",
        )
        for table, (file, line) in sorted(created.items())
        if table not in enabled
    ]


def check_firebase_rules(project: Project) -> list[Finding]:
    out: list[Finding] = []
    for path in project.files:
        name = path.name
        rel = _rel(project, path)
        if name.endswith(".rules"):
            text = _read(path)
            for m in _FIRESTORE_OPEN.finditer(text):
                out.append(
                    _finding(
                        "vibe-firebase-rules-open",
                        "Firebase rules let anyone read or write — your data is public",
                        Severity.CRITICAL,
                        rel,
                        _line_of(text, m.start()),
                        "An allow rule with no condition (or `if true`) applies to every visitor, "
                        "logged in or not.",
                        "Only allow signed-in users to their own data: allow read, write: if "
                        "request.auth != null && request.auth.uid == userId;",
                    )
                )
            for m in _FIRESTORE_TEST_MODE.finditer(text):
                out.append(
                    _finding(
                        "vibe-firebase-test-mode",
                        "Firebase rules are still in test mode — open to everyone until the date in the rule",
                        Severity.HIGH,
                        rel,
                        _line_of(text, m.start()),
                        "Test-mode rules allow all reads and writes until a date, then lock you out. "
                        "Until then the database is public.",
                        "Replace the time check with real rules based on request.auth.",
                    )
                )
        elif name == "database.rules.json":
            text = _read(path)
            for m in _RTDB_OPEN.finditer(text):
                out.append(
                    _finding(
                        "vibe-firebase-rules-open",
                        "Realtime Database rules let anyone read or write — your data is public",
                        Severity.CRITICAL,
                        rel,
                        _line_of(text, m.start()),
                        '".read": true / ".write": true applies to every visitor.',
                        'Use rules based on auth: ".read": "auth != null && auth.uid === $uid".',
                    )
                )
    return out


def _is_browser_file(project: Project, path: Path, text: str) -> bool:
    rel = _rel(project, path)
    if path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte"}:
        return False
    if _USE_CLIENT.search(text[:500]):
        return True
    parts = rel.split("/")
    # Server-only by convention: *.server.ts (TanStack Start, Remix, SvelteKit), server/api dirs,
    # Supabase / Netlify / Firebase functions.
    if ".server." in path.name.lower() or any(
        p in {"server", "api", "functions", "edge-functions", "netlify", "scripts"}
        for p in parts[:-1]
    ):
        return False
    if project.vite and parts[0] == "src":
        return True
    return parts[0] in {"components"} or rel.startswith("src/components/")


def check_service_role_in_browser(project: Project) -> list[Finding]:
    if not project.supabase:
        return []
    out: list[Finding] = []
    for path in project.files:
        rel = _rel(project, path)
        if path_context(rel):
            continue
        text = _read(path) if path.suffix.lower() in _CODE_EXT else ""
        if not text or not _is_browser_file(project, path, text):
            continue
        m = _SERVICE_ROLE_REF.search(text)
        if m:
            out.append(
                _finding(
                    "vibe-supabase-service-role-in-browser",
                    "Supabase service_role key used in browser code — it bypasses every database rule",
                    Severity.CRITICAL,
                    rel,
                    _line_of(text, m.start()),
                    "This file runs in the visitor's browser. Whatever key it uses can be copied from "
                    "there, and service_role ignores Row Level Security.",
                    "Use the anon key in browser code. Do privileged work in a server route or edge "
                    "function that reads the service key from a server-only env variable, and rotate it.",
                    cwe="CWE-522",
                )
            )
    return out


def check_unprotected_mutations(project: Project) -> list[Finding]:
    out: list[Finding] = []
    confidence = "low" if project.middleware_auth else "medium"
    note = (
        f" ({project.middleware_auth} has an auth check; make sure it covers this route)"
        if project.middleware_auth
        else ""
    )
    for path in project.files:
        rel = _rel(project, path)
        suffix = path.suffix.lower()
        if suffix not in _CODE_EXT or path_context(rel):
            continue
        text = _read(path)
        changes_data = bool(_DATA_CHANGE.search(text)) or (
            suffix == ".py" and bool(_PY_DATA_CHANGE.search(text))
        )
        if not text or not changes_data or _AUTH_EVIDENCE.search(text):
            continue
        location: tuple[int, str] | None = None
        if suffix == ".py":
            m = _PY_MUTATION_ROUTE.search(text)
            if m and _PY_DATA_CHANGE.search(text):
                location = (_line_of(text, m.start()), "endpoint")
        else:
            name = path.name.rsplit(".", 1)[0]
            m = _ROUTE_MUTATION.search(text)
            if m and (name == "route" or "/api/" in f"/{rel}"):
                location = (_line_of(text, m.start()), f"{m.group(1) or m.group(2)} handler")
            elif rel.startswith(("pages/api/", "src/pages/api/")) and "export default" in text:
                location = (_line_of(text, text.index("export default")), "API route")
            elif _USE_SERVER.search(text[:500]):
                m = _SERVER_ACTION.search(text)
                if m:
                    location = (_line_of(text, m.start()), "server action")
        if location:
            out.append(
                _finding(
                    "vibe-unprotected-mutation",
                    f"This {location[1]} changes data but never checks who is calling it",
                    Severity.HIGH,
                    rel,
                    location[0],
                    "Anyone can call it directly (curl, the browser console), even if your UI only "
                    "shows the button to logged-in users or admins." + note,
                    "Check the user at the top of the handler (e.g. const user = await getUser(); if "
                    "(!user) return 401) and that they own the record they change.",
                    confidence=confidence,
                    cwe="CWE-306",
                )
            )
    return out


def vibe_findings(target: str) -> tuple[list[Finding], dict[str, object]]:
    project = discover(Path(target))
    findings: list[Finding] = []
    for check in (
        check_env_files,
        check_supabase_rls,
        check_firebase_rules,
        check_service_role_in_browser,
        check_unprotected_mutations,
    ):
        findings.extend(check(project))
    metadata: dict[str, object] = {
        "stack": [
            s
            for s, on in (
                ("supabase", project.supabase),
                ("firebase", project.firebase),
                ("vite", project.vite),
            )
            if on
        ]
        + (["next"] if '"next"' in project.package_json else []),
        "middleware_auth": project.middleware_auth,
        "files": len(project.files),
    }
    return findings, metadata


async def run_vibe_checks(target: str) -> ScanResult:
    result = ScanResult(tool=TOOL, scan_type=ScanType.SAST, target=target)
    try:
        findings, metadata = await asyncio.to_thread(vibe_findings, target)
    except Exception as exc:  # never break a scan
        result.errors.append(f"argus-vibe error: {exc}")
        return result
    result.findings.extend(findings)
    result.metadata.update(metadata)
    return result
