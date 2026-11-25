"""Missing HTTP security headers (CSP, HSTS, X-Frame-Options, nosniff) (#198).

A *missing* control, so it's a project-level check like abuse_controls (#191):

1. decide whether the project is a web app (framework in a manifest, or HTTP routes), then
2. look anywhere in non-test code, config and infrastructure files for evidence that security
   headers are set (helmet, talisman, Spring Security, secure_headers, nginx add_header,
   hosting header config, or the header names themselves).

A gap is reported only for a web app with no evidence at all. Explicit downgrades
(``headers().disable()``, ``contentSecurityPolicy: false``, ``SECURE_HSTS_SECONDS = 0``,
``X-Frame-Options: ALLOWALL``) are reported on their own line. Files are read, never run.
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from argus_languages.noise import path_context

from argus.models import Finding, ScanResult, ScanType, Severity
from argus.tools.abuse_controls import _MANIFESTS, _SKIP_DIRS, _SOURCE_SUFFIXES, find_endpoints

TOOL_NAME = "argus-security-headers"
_MAX_FILE = 1024 * 1024
_SUFFIXES = _SOURCE_SUFFIXES | {".tf", ".rb", ".erb"}
# Hosting header config without a useful suffix (Netlify / Cloudflare Pages, Apache).
_EXTRA_NAMES = frozenset({"_headers", ".htaccess", "Caddyfile", "web.config"})

# Framework markers in manifests and entry files: (label, pattern, serves HTML pages).
_FRAMEWORKS: tuple[tuple[str, re.Pattern[str], bool], ...] = (
    ("Next.js", re.compile(r'"next"\s*:'), True),
    ("Nuxt", re.compile(r'"nuxt"\s*:'), True),
    ("NestJS", re.compile(r'"@nestjs/core"\s*:'), False),
    ("Express", re.compile(r'"express"\s*:'), False),
    ("Fastify", re.compile(r'"fastify"\s*:'), False),
    ("Koa", re.compile(r'"koa"\s*:'), False),
    ("Hono", re.compile(r'"hono"\s*:'), False),
    ("Django", re.compile(r"^\s*django\b|['\"]django[>=<~\[\"']", re.I | re.M), True),
    ("Flask", re.compile(r"^\s*flask\b|['\"]flask[>=<~\[\"']", re.I | re.M), True),
    ("FastAPI", re.compile(r"^\s*fastapi\b|['\"]fastapi[>=<~\[\"']", re.I | re.M), False),
    ("Spring Boot", re.compile(r"spring-boot-starter-web"), True),
    ("Laravel", re.compile(r'"laravel/framework"\s*:'), True),
    ("Symfony", re.compile(r'"symfony/framework-bundle"\s*:'), True),
    ("Rails", re.compile(r"^\s*gem\s+['\"]rails['\"]", re.M), True),
    ("ASP.NET Core", re.compile(r'Sdk="Microsoft\.NET\.Sdk\.Web"'), True),
    (
        "Go web",
        re.compile(r"github\.com/(gin-gonic/gin|labstack/echo|go-chi/chi|gofiber/fiber)"),
        False,
    ),
)
_FRAMEWORK_FILES = frozenset(
    {
        "package.json",
        "requirements.txt",
        "pyproject.toml",
        "Pipfile",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "composer.json",
        "Gemfile",
        "go.mod",
    }
)
_PAGE_SUFFIXES = frozenset(
    {
        ".html",
        ".htm",
        ".jsx",
        ".tsx",
        ".vue",
        ".svelte",
        ".erb",
        ".ejs",
        ".hbs",
        ".jinja",
        ".j2",
        ".cshtml",
        ".razor",
    }
)

_HEADER_EVIDENCE = re.compile(
    # The headers themselves (manual middleware, next.config headers(), nginx, hosting config)
    r"Content-Security-Policy|Strict-Transport-Security"
    # Node
    r"|\bhelmet\b|@fastify/helmet|koa-helmet|next-secure-headers|@nextjs/secure-headers"
    # Python
    r"|flask[_-]talisman|\bTalisman\s*\(|django[_-]csp|\bCSP_DEFAULT_SRC\b|CONTENT_SECURITY_POLICY"
    r"|SECURE_HSTS_SECONDS\s*=\s*[1-9]|\bsecure\.Secure\(|from\s+secure\s+import"
    # Java (Spring Security sets headers by default)
    r"|spring-boot-starter-security|@EnableWebSecurity|contentSecurityPolicy\s*\("
    # PHP / Ruby / .NET / Go
    r"|spatie/laravel-csp|nelmio/security-bundle|nelmio_security|bepsvpt/secure-headers"
    r"|secure_headers|content_security_policy|config\.force_ssl"
    r"|\bUseHsts\s*\(|NWebsec|NetEscapades\.AspNetCore\.SecurityHeaders|UseSecurityHeaders"
    r"|unrolled/secure"
    # Infrastructure
    r"|aws_cloudfront_response_headers_policy|ResponseHeadersPolicy|security_headers_config",
    re.IGNORECASE,
)

_JS = frozenset({".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"})
_JVM = frozenset({".java", ".kt", ".kts", ".scala"})
_ANY: frozenset[str] = frozenset()  # empty = every scanned file

# Lockfiles list transitive packages: helmet there doesn't mean the app uses it.
_LOCKFILES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "composer.lock",
        "poetry.lock",
        "uv.lock",
        "Pipfile.lock",
        "Gemfile.lock",
        "go.sum",
        "Cargo.lock",
        "packages.lock.json",
    }
)

# (rule id, title, severity, file suffixes, pattern, fix)
_DOWNGRADES: tuple[tuple[str, str, Severity, frozenset[str], re.Pattern[str], str], ...] = (
    (
        "security-headers-disabled",
        "Spring Security response headers disabled — no HSTS, frame or nosniff protection",
        Severity.HIGH,
        _JVM,
        re.compile(
            r"\.headers\(\s*\)\s*\.disable\(\)|\.headers\(\s*\w+\s*->\s*\w+\.disable\(\)\s*\)"
            r"|\.headers\(\s*AbstractHttpConfigurer::disable\s*\)"
        ),
        "Remove the headers().disable() call. To relax one header, configure it instead, for "
        "example .headers(h -> h.frameOptions(f -> f.sameOrigin())).",
    ),
    (
        "x-frame-options-allowall",
        "X-Frame-Options: ALLOWALL — any site can frame these pages (clickjacking)",
        Severity.HIGH,
        _ANY,
        # Header-setting syntax only: nginx/Apache directives, quoted name/value pairs, or a raw
        # "X-Frame-Options: ALLOWALL" header line (Netlify _headers).
        re.compile(
            r"(?:add_header|Header\s+(?:always\s+)?set)\s+X-Frame-Options\s+['\"]?ALLOWALL"
            r"|['\"]X-Frame-Options['\"]\s*[:,=]\s*['\"]ALLOWALL['\"]"
            r"|^\s*X-Frame-Options:\s*ALLOWALL\s*$",
            re.I | re.M,
        ),
        "Use X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors listing the sites "
        "allowed to embed you.",
    ),
    (
        "helmet-protection-disabled",
        "helmet protection switched off (contentSecurityPolicy, hsts or frameguard: false)",
        Severity.MEDIUM,
        _JS,
        re.compile(
            r"\b(contentSecurityPolicy|hsts|frameguard|strictTransportSecurity|xFrameOptions)\s*:\s*false\b"
        ),
        "Keep the header and configure it instead of disabling it, for example a CSP with the "
        "sources your pages need. Pure JSON APIs may skip CSP; keep HSTS and frame protection.",
    ),
    (
        "django-hsts-disabled",
        "SECURE_HSTS_SECONDS = 0 — HSTS is off, so browsers accept HTTP downgrades",
        Severity.MEDIUM,
        frozenset({".py"}),
        re.compile(r"^\s*SECURE_HSTS_SECONDS\s*=\s*0\b", re.M),
        "Set SECURE_HSTS_SECONDS to at least 31536000 in production (start lower while testing) "
        "with SECURE_HSTS_INCLUDE_SUBDOMAINS = True.",
    ),
)

_FIX_BY_FRAMEWORK = {
    "Next.js": "Add headers() in next.config.js returning Content-Security-Policy, "
    "Strict-Transport-Security, X-Content-Type-Options and X-Frame-Options (or frame-ancestors).",
    "Nuxt": "Use the nuxt-security module, or set the headers in routeRules / your proxy.",
    "NestJS": "app.use(helmet()) in main.ts (npm install helmet).",
    "Express": "app.use(helmet()) (npm install helmet).",
    "Fastify": "await app.register(import('@fastify/helmet')).",
    "Koa": "app.use(helmet()) with koa-helmet.",
    "Hono": "app.use(secureHeaders()) from hono/secure-headers.",
    "Django": "Keep SecurityMiddleware, set SECURE_HSTS_SECONDS, SECURE_CONTENT_TYPE_NOSNIFF and "
    "X_FRAME_OPTIONS, and add django-csp for a Content-Security-Policy.",
    "Flask": "Wrap the app with Talisman(app) (flask-talisman).",
    "FastAPI": "Add a middleware that sets the headers (or the secure package), or set them at "
    "the proxy.",
    "Spring Boot": "Add spring-boot-starter-security: its default headers include HSTS, "
    "nosniff and frame options; add .contentSecurityPolicy(...) for CSP.",
    "Laravel": "Add a header middleware (bepsvpt/secure-headers) and spatie/laravel-csp.",
    "Symfony": "Use nelmio/security-bundle.",
    "Rails": "Configure config/initializers/content_security_policy.rb and config.force_ssl.",
    "ASP.NET Core": "app.UseHsts() in production plus a security-headers middleware "
    "(NetEscapades.AspNetCore.SecurityHeaders) for CSP and frame options.",
    "Go web": "Use unrolled/secure (or set the headers in a middleware).",
}


@dataclass
class HeaderEvidence:
    frameworks: list[str] = field(default_factory=list)
    framework_at: str | None = None  # file:line of the first framework marker
    serves_pages: bool = False
    first_route: str | None = None
    headers: str | None = None  # file:line of the first header evidence
    downgrades: list[Finding] = field(default_factory=list)


def _iter_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            suffix = path.suffix.lower()
            if (
                suffix in _SUFFIXES
                or suffix in _PAGE_SUFFIXES
                or name in _MANIFESTS
                or name in _EXTRA_NAMES
                or name.startswith(("next.config.", "nginx"))
            ):
                files.append(path)
    return files


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def collect(root: Path) -> HeaderEvidence:
    base = root if root.is_dir() else root.parent
    ev = HeaderEvidence()
    for path in _iter_files(root):
        relative = path.relative_to(base).as_posix()
        if path_context(relative):  # tests, docs, examples and generated files
            continue
        suffix = path.suffix.lower()
        if suffix in _PAGE_SUFFIXES:
            ev.serves_pages = True
            if suffix not in _SUFFIXES:
                continue
        try:
            if path.stat().st_size > _MAX_FILE:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if path.name in _FRAMEWORK_FILES or path.suffix.lower() == ".csproj":
            for label, pattern, pages in _FRAMEWORKS:
                match = pattern.search(text)
                if match and label not in ev.frameworks:
                    ev.frameworks.append(label)
                    ev.serves_pages = ev.serves_pages or pages
                    ev.framework_at = (
                        ev.framework_at or f"{relative}:{_line_of(text, match.start())}"
                    )
        if ev.first_route is None:
            routes = find_endpoints(text, relative)
            if routes:
                ev.first_route = f"{routes[0].file}:{routes[0].line}"
        if ev.headers is None and path.name not in _LOCKFILES:
            match = _HEADER_EVIDENCE.search(text)
            if match:
                ev.headers = f"{relative}:{_line_of(text, match.start())}"
        for rule_id, title, severity, suffixes, pattern, fix in _DOWNGRADES:
            if suffixes and suffix not in suffixes:
                continue
            for match in pattern.finditer(text):
                ev.downgrades.append(
                    _finding(
                        rule_id,
                        title,
                        severity,
                        "high",
                        relative,
                        _line_of(text, match.start()),
                        "Security headers are explicitly turned off here.",
                        fix,
                    )
                )
    return ev


def _finding(
    rule_id: str,
    title: str,
    severity: Severity,
    confidence: str,
    file: str,
    line: int,
    detail: str,
    fix: str,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        scan_type=ScanType.SAST,
        tool=TOOL_NAME,
        file=file,
        line=line,
        rule_id=rule_id,
        confidence=confidence,
        description=detail,
        fix_guidance=fix,
        cwe="CWE-693",
        references=[
            "https://owasp.org/www-project-secure-headers/",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
        ],
    )


def security_header_findings(target: str) -> tuple[list[Finding], dict[str, object]]:
    ev = collect(Path(target))
    is_web_app = bool(ev.frameworks) or ev.first_route is not None
    metadata: dict[str, object] = {
        "web_app": is_web_app,
        "frameworks": ev.frameworks,
        "header_evidence": ev.headers,
        "downgrades": len(ev.downgrades),
    }
    findings = list(ev.downgrades)
    if is_web_app and ev.headers is None:
        where = ev.framework_at or ev.first_route or "."
        file, _, line = where.rpartition(":")
        if not file:
            file, line = where, "0"
        names = ", ".join(ev.frameworks) or "HTTP routes"
        fixes = [_FIX_BY_FRAMEWORK[f] for f in ev.frameworks if f in _FIX_BY_FRAMEWORK]
        fix = " ".join(fixes[:2]) or (
            "Set Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options: "
            "nosniff and X-Frame-Options (or CSP frame-ancestors) in the app or at the proxy."
        )
        pages = ev.serves_pages
        findings.append(
            _finding(
                "security-headers-missing",
                f"No HTTP security headers found for this web app ({names})"
                + ("" if pages else " — review"),
                Severity.MEDIUM if pages else Severity.LOW,
                "low",
                file,
                int(line) if line.isdigit() else 0,
                "No Content-Security-Policy, HSTS or security-header middleware was found anywhere "
                "in the project. Without them XSS is easier to exploit, pages can be framed "
                "(clickjacking) and browsers accept HTTP downgrades. A proxy, CDN or hosting "
                "config outside this repository may already set them; if so, ignore this finding.",
                fix,
            )
        )
    return findings, metadata


async def run_security_headers_check(target: str) -> ScanResult:
    result = ScanResult(tool=TOOL_NAME, scan_type=ScanType.SAST, target=target)
    findings, metadata = await asyncio.to_thread(security_header_findings, target)
    result.findings.extend(findings)
    result.metadata.update(metadata)
    return result
