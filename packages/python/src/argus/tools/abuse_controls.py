"""Missing API rate limiting and missing login lockout (#191).

These are *missing* controls, so line rules can't see them. The check is project-level:

1. find sensitive HTTP endpoints (login, token, password reset, OTP, register, …) in the route
   definitions of common frameworks, then
2. look anywhere in the project's non-test code and manifests for evidence of a rate limiter,
   an account-lockout mechanism, or an external identity provider that handles login.

A gap is reported only when endpoints exist and the evidence doesn't. Files are read, never run.
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from pathlib import Path

from argus_languages.noise import path_context

from argus.models import Finding, ScanResult, ScanType, Severity

TOOL_NAME = "argus-abuse-controls"
_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        ".next",
        "target",
        "coverage",
        ".tox",
        "vendor",
        ".gradle",
        ".mvn",
    }
)
_SOURCE_SUFFIXES = frozenset(
    {
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".jsx",
        ".tsx",
        ".py",
        ".java",
        ".kt",
        ".kts",
        ".scala",
        ".php",
        ".rb",
        ".go",
        ".cs",
        ".rs",
        ".ex",
        ".exs",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".xml",
        ".gradle",
        ".conf",
        ".properties",
        ".csproj",
    }
)
_MANIFESTS = frozenset(
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
        "Cargo.toml",
        "mix.exs",
        "nginx.conf",
        "packages.config",
    }
)
_MAX_FILE = 1024 * 1024

# Path words that make an endpoint worth brute-forcing or abusing.
_SENSITIVE = re.compile(
    r"log-?in|sign-?in|sign-?on|\bauth(?:enticate|orize)?\b|/auth|token|oauth|password|passwd"
    r"|reset|forgot|\botp\b|2fa|mfa|totp|verif|register|sign-?up|confirm|magic-?link|session",
    re.IGNORECASE,
)
# Endpoints that check a credential (lockout applies to these).
_CREDENTIAL = re.compile(r"log-?in|sign-?in|sign-?on|authenticate|/token|session|/auth/?$", re.I)

_Q = r"""['"`]"""
_JS = frozenset({".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"})
_PY = frozenset({".py"})
_JVM = frozenset({".java", ".kt", ".kts", ".scala"})
_P = r"([^'\"`]*)"

# (file suffixes, pattern). Each framework's pattern only runs on its own language, so a Python
# dict lookup like r.get("findings") is never read as an Express route.
_ROUTE_PATTERNS: tuple[tuple[frozenset[str], re.Pattern[str]], ...] = (
    # Express / Koa / Fastify / Hono:  app.post("/login", …). Paths start with "/" (app.get("env")
    # is an Express settings getter, not a route).
    (
        _JS,
        re.compile(
            r"\b(?:app|router|server|api|fastify|routes?|r)\.(?:post|put|patch|all|route|get|delete)\s*\(\s*"
            + _Q
            + r"(/[^'\"`]*)"
            + _Q
        ),
    ),
    # NestJS / Spring / Micronaut method decorators:  @Post('login'), @PostMapping("/login")
    (
        _JS | _JVM,
        re.compile(
            r"@(?:Post|Put|Patch|All|Get|Delete)(?:Mapping)?\s*\(\s*(?:\{[^}]*?path\s*:\s*)?(?:(?:value|path)\s*=\s*)?\{?\s*"
            + _Q
            + _P
            + _Q
        ),
    ),
    # Flask / FastAPI / Bottle:  @app.route("/login", methods=["POST"]), @router.post("/token")
    (
        _PY,
        re.compile(r"@\w+\.(?:route|post|put|patch|get|delete|api_route)\s*\(\s*" + _Q + _P + _Q),
    ),
    # Django:  path("login/", …), re_path(r"^login/$", …)
    (_PY, re.compile(r"(?<![\w.])(?:re_)?path\s*\(\s*r?" + _Q + _P + _Q)),
    # aiohttp / Starlette:  app.router.add_post("/login", h), Route("/login", h, methods=…)
    (
        _PY,
        re.compile(
            r"\.add_(?:post|put|patch|get|route)\s*\(\s*(?:"
            + _Q
            + r"[A-Z]+"
            + _Q
            + r"\s*,\s*)?"
            + _Q
            + _P
            + _Q
        ),
    ),
    (_PY, re.compile(r"(?<![\w.])Route\s*\(\s*" + _Q + r"(/[^'\"`]*)" + _Q)),
    # Laravel:  Route::post('/login', …);  Slim:  $app->post('/login', …)
    (
        frozenset({".php"}),
        re.compile(r"Route::(?:post|put|patch|match|any|get|delete)\s*\(\s*" + _Q + _P + _Q),
    ),
    (
        frozenset({".php"}),
        re.compile(
            r"\$(?:app|router|group)->(?:post|put|patch|map|any|get|delete)\s*\(\s*" + _Q + _P + _Q
        ),
    ),
    # Symfony attributes / annotations:  #[Route('/login', methods: ['POST'])]
    (frozenset({".php"}), re.compile(r"[#@]\[?Route\s*\(\s*(?:path\s*:\s*)?" + _Q + _P + _Q)),
    # Rails routes.rb / Sinatra:  post "login", to: …  /  post '/login' do
    (
        frozenset({".rb"}),
        re.compile(r"^\s*(?:post|put|patch|match|get|delete)\s+" + _Q + _P + _Q, re.M),
    ),
    # Go net/http / gin / echo / chi / Fiber:  r.POST("/login", …), http.HandleFunc("/login", …)
    (
        frozenset({".go"}),
        re.compile(
            r"\.(?:POST|PUT|PATCH|GET|DELETE|Post|Put|Patch|Get|Delete|HandleFunc|Handle)\s*\(\s*\"([^\"]*)\""
        ),
    ),
    # Spring WebFlux router functions:  POST("/login", handler::login)
    (_JVM, re.compile(r"(?<![\w.])(?:POST|PUT|PATCH)\s*\(\s*\"([^\"]*)\"")),
    # JAX-RS:  @Path("/login");  Kotlin Ktor routing:  post("/login") {
    (_JVM, re.compile(r"@Path\s*\(\s*\"([^\"]*)\"")),
    (
        frozenset({".kt", ".kts"}),
        re.compile(r"^\s*(?:post|put|patch|get|delete)\s*\(\s*\"([^\"]*)\"\s*\)\s*\{", re.M),
    ),
    # C# / ASP.NET Core:  [HttpPost("login")], [Route("api/auth")], app.MapPost("/login", …)
    (
        frozenset({".cs"}),
        re.compile(r"\[(?:Http(?:Post|Put|Patch|Get|Delete)|Route)\s*\(\s*\"([^\"]*)\""),
    ),
    (
        frozenset({".cs"}),
        re.compile(r"\.Map(?:Post|Put|Patch|Get|Delete|Methods)\s*\(\s*\"([^\"]*)\""),
    ),
    # Rust actix-web / rocket attributes and axum:  #[post("/login")], .route("/login", post(h))
    (frozenset({".rs"}), re.compile(r"#\[(?:post|put|patch|get|delete)\s*\(\s*\"([^\"]*)\"")),
    (
        frozenset({".rs"}),
        re.compile(r"\.route\s*\(\s*\"([^\"]*)\"\s*,\s*(?:\w+::)*(?:post|put|patch|get|delete)\b"),
    ),
    # Elixir Phoenix router:  post "/login", SessionController, :create
    (
        frozenset({".ex", ".exs"}),
        re.compile(r"^\s*(?:post|put|patch|get|delete)\s+\"([^\"]*)\"\s*,", re.M),
    ),
)
_COMMENT_LINE = re.compile(r"^\s*(?://|#(?![\[!])|/?\*|--|<!--)")
# Controller-level prefixes: @Controller('auth') / @RequestMapping("/api/auth") on a class.
_PREFIX = re.compile(
    r"@(?:Controller|RequestMapping)\s*\(\s*(?:\{[^}]*?path\s*:\s*)?(?:(?:value|path)\s*=\s*)?"
    + _Q
    + r"([^'\"`]*)"
    + _Q
)
_BARE_POST = re.compile(r"@(?:Post|PostMapping)\s*\(\s*\)")

_RATE_LIMIT_EVIDENCE = re.compile(
    r"express-rate-limit|rate-limiter-flexible|express-slow-down|express-brute|@nestjs/throttler"
    r"|ThrottlerModule|ThrottlerGuard|@Throttle\b|@SkipThrottle\b|fastify-rate-limit|@fastify/rate-limit"
    r"|koa-?2?-ratelimit|hono-rate-limiter|flask[_-]limiter|\bslowapi\b|fastapi[_-]limiter"
    r"|django[_-]ratelimit|@ratelimit\b|throttle_classes|DEFAULT_THROTTLE_CLASSES|AnonRateThrottle"
    r"|UserRateThrottle|ScopedRateThrottle|bucket4j|resilience4j|RateLimiter|rateLimiter|rate_limiter"
    r"|\brateLimit\b|\brate_limit\b|@RateLimit\b|RateLimitGuard|['\"]throttle:|ThrottleRequests"
    r"|RateLimiter::for|rack-attack|Rack::Attack|golang\.org/x/time/rate|tollbooth|ulule/limiter"
    r"|limit_req_zone|\blimit_req\b"
    # .NET, Go, Rust, Elixir, PHP Symfony
    r"|AddRateLimiter|RequireRateLimiting|EnableRateLimiting|AspNetCoreRateLimit|IpRateLimiting"
    r"|go-chi/httprate|\bhttprate\b|middleware/limiter|redis_rate|\bgovernor\b|tower_governor"
    r"|actix-governor|actix_governor|\bhammer\b|PlugAttack|plug_attack|symfony/rate-limiter"
    r"|login_throttling",
    re.IGNORECASE,
)
_LOCKOUT_EVIDENCE = re.compile(
    r"lock_?out|lockedUntil|locked_until|lockUntil|lock_until|account_?locked|accountLocked"
    r"|isLocked|is_locked|failed_?(?:login_?)?attempts?|failedAttempts|failedLogin|failed_login"
    r"|login_?attempts?|loginAttempts|max_?(?:login_?|failed_?)?attempts|MAX_(?:LOGIN_|FAILED_)?ATTEMPTS"
    r"|django-axes|django_axes|\baxes\b|ThrottlesLogins|LockedException|accountNonLocked"
    r"|AuthenticationFailureLocked|consecutive_?fail|consecutiveFail|limiterConsecutiveFails"
    r"|incorrect_?attempts|brute[-_ ]?force"
    # .NET Identity, Symfony
    r"|lockoutOnFailure:\s*true|MaxFailedAccessAttempts|DefaultLockoutTimeSpan|AllowedForNewUsers"
    r"|AccessFailedAsync|login_throttling",
    re.IGNORECASE,
)
# Login handled by an identity provider: lockout is the provider's job.
_IDENTITY_PROVIDER = re.compile(
    r"\bauth0\b|@auth0/|amazon-cognito|aws-amplify|CognitoIdentity|keycloak|@okta/|okta-|"
    r"firebase/auth|firebase-admin|@clerk/|clerk\.com|supabase\.auth|@supabase/|@azure/msal|msal\b"
    r"|passport-azure-ad|next-auth|@auth/core|better-auth|lucia-auth|ory/kratos|stytch|workos|descope"
    r"|spring-security-oauth2-client|oauth2Login\(|social-auth-app|django-allauth",
    re.IGNORECASE,
)


@dataclass
class Endpoint:
    path: str
    file: str
    line: int


def _iter_project_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() in _SOURCE_SUFFIXES or name in _MANIFESTS:
                files.append(path)
    return files


def find_endpoints(text: str, relative: str) -> list[Endpoint]:
    suffix = Path(relative).suffix.lower()
    patterns = [pattern for suffixes, pattern in _ROUTE_PATTERNS if suffix in suffixes]
    if not patterns:
        return []
    # Blank out comment lines (keeps line numbers): routes in comments aren't routes.
    text = "\n".join("" if _COMMENT_LINE.match(line) else line for line in text.split("\n"))
    endpoints: list[Endpoint] = []
    prefix_match = _PREFIX.search(text) if suffix in _JS | _JVM else None
    prefix = prefix_match.group(1) if prefix_match else ""
    for pattern in patterns:
        for match in pattern.finditer(text):
            path = match.group(1).strip()
            if not path and not prefix:
                continue
            full = f"/{prefix.strip('/')}/{path.strip('/')}".replace("//", "/") if prefix else path
            endpoints.append(
                Endpoint(full or "/", relative, text.count("\n", 0, match.start()) + 1)
            )
    if prefix:  # @Post() with no path inherits the controller prefix
        for match in _BARE_POST.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            endpoints.append(Endpoint(f"/{prefix.strip('/')}", relative, line))
    return endpoints


@dataclass
class ProjectEvidence:
    endpoints: list[Endpoint]
    rate_limit: str | None = None  # first evidence found: "file:line"
    lockout: str | None = None
    identity_provider: str | None = None


def collect(root: Path) -> ProjectEvidence:
    base = root if root.is_dir() else root.parent
    evidence = ProjectEvidence(endpoints=[])
    for path in _iter_project_files(root):
        relative = path.relative_to(base).as_posix()
        if path_context(relative):  # tests, docs, examples and generated files don't protect prod
            continue
        try:
            if path.stat().st_size > _MAX_FILE:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if path.suffix.lower() not in {".json", ".toml", ".xml", ".gradle", ".conf", ".properties"}:
            evidence.endpoints.extend(find_endpoints(text, relative))
        for attr, pattern in (
            ("rate_limit", _RATE_LIMIT_EVIDENCE),
            ("lockout", _LOCKOUT_EVIDENCE),
            ("identity_provider", _IDENTITY_PROVIDER),
        ):
            if getattr(evidence, attr) is None:
                match = pattern.search(text)
                if match:
                    setattr(
                        evidence, attr, f"{relative}:{text.count(chr(10), 0, match.start()) + 1}"
                    )
    return evidence


def _listing(endpoints: list[Endpoint]) -> str:
    shown = ", ".join(f"{e.path} ({e.file}:{e.line})" for e in endpoints[:5])
    more = f" and {len(endpoints) - 5} more" if len(endpoints) > 5 else ""
    return shown + more


def abuse_control_findings(target: str) -> tuple[list[Finding], dict[str, object]]:
    evidence = collect(Path(target))
    sensitive = [e for e in evidence.endpoints if _SENSITIVE.search(e.path)]
    credential = [e for e in sensitive if _CREDENTIAL.search(e.path)]
    metadata: dict[str, object] = {
        "endpoints": len(evidence.endpoints),
        "sensitive_endpoints": len(sensitive),
        "rate_limit_evidence": evidence.rate_limit,
        "lockout_evidence": evidence.lockout,
        "identity_provider": evidence.identity_provider,
    }
    findings: list[Finding] = []

    def finding(
        rule_id: str,
        title: str,
        severity: Severity,
        confidence: str,
        at: Endpoint,
        detail: str,
        fix: str,
    ) -> Finding:
        return Finding(
            title=title,
            severity=severity,
            scan_type=ScanType.SAST,
            tool=TOOL_NAME,
            file=at.file,
            line=at.line,
            rule_id=rule_id,
            confidence=confidence,
            description=detail,
            fix_guidance=fix,
            cwe="CWE-307" if "lockout" in rule_id else "CWE-770",
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            ],
        )

    rate_fix = (
        "Add a rate limiter in front of these routes (express-rate-limit / @nestjs/throttler, "
        "Flask-Limiter / slowapi, DRF throttling, Bucket4j, Laravel throttle middleware, "
        "Rack::Attack) keyed by IP and by account, with stricter limits on login, reset and OTP."
    )
    if sensitive and not evidence.rate_limit:
        findings.append(
            finding(
                "api-rate-limit-missing",
                f"No rate limiting found for {len(sensitive)} sensitive endpoint(s) (login, reset, OTP, token…)",
                Severity.MEDIUM,
                "medium",
                sensitive[0],
                "Without a rate limit these endpoints allow credential stuffing, password and OTP "
                f"brute force, and SMS/email bombing. Endpoints: {_listing(sensitive)}.",
                rate_fix,
            )
        )
    elif evidence.endpoints and not sensitive and not evidence.rate_limit:
        findings.append(
            finding(
                "api-rate-limit-missing-general",
                f"HTTP API with {len(evidence.endpoints)} route(s) and no rate limiting found — review",
                Severity.LOW,
                "low",
                evidence.endpoints[0],
                "No rate limiter was found anywhere in the project. Unlimited requests make "
                "scraping and resource-exhaustion (DoS) easy. A gateway or proxy may already "
                "handle this; if so, ignore this finding.",
                rate_fix,
            )
        )
    if credential and not evidence.lockout and not evidence.identity_provider:
        rate_limited = evidence.rate_limit is not None
        findings.append(
            finding(
                "auth-lockout-missing",
                (
                    "Login is rate limited but has no per-account lockout — review"
                    if rate_limited
                    else "No account lockout or failed-login tracking found for login endpoints"
                ),
                Severity.LOW if rate_limited else Severity.MEDIUM,
                "low",
                credential[0],
                (
                    "Rate limiting slows guessing per client, but a distributed attack (many IPs, "
                    "one account) still gets through without a per-account lockout or "
                    f"progressive delay. Login endpoints: {_listing(credential)}."
                    if rate_limited
                    else "Nothing counts failed logins or locks an account, so passwords can be "
                    f"guessed without limit. Login endpoints: {_listing(credential)}."
                ),
                "Track failed attempts per account; after N failures add a growing delay or a "
                "temporary lock (and notify the user). Libraries: rate-limiter-flexible "
                "(consecutive-fail limiter), django-axes, Laravel ThrottlesLogins, Spring "
                "Security's lockout via UserDetails.isAccountNonLocked.",
            )
        )
    return findings, metadata


async def run_abuse_control_check(target: str) -> ScanResult:
    result = ScanResult(tool=TOOL_NAME, scan_type=ScanType.SAST, target=target)
    findings, metadata = await asyncio.to_thread(abuse_control_findings, target)
    result.findings.extend(findings)
    result.metadata.update(metadata)
    return result
