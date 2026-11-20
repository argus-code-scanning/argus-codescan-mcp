"""Missing API rate limiting and login lockout (#191), across languages and frameworks."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.models import Severity
from argus.tools.abuse_controls import abuse_control_findings, run_abuse_control_check

# (language/framework, file, unprotected login route, rate-limit evidence for that ecosystem)
APPS = [
    (
        "Express",
        "src/server.js",
        "app.post('/api/login', login);",
        "const rateLimit = require('express-rate-limit');",
    ),
    (
        "NestJS",
        "src/auth.controller.ts",
        "@Controller('auth')\nexport class A {\n  @Post('login')\n  login() {}\n}",
        "import { ThrottlerModule } from '@nestjs/throttler';",
    ),
    (
        "NestJS bare @Post",
        "src/session.controller.ts",
        "@Controller('session')\nexport class S {\n  @Post()\n  create() {}\n}",
        "@Throttle({ default: { limit: 5, ttl: 60000 } })",
    ),
    (
        "Fastify",
        "src/app.ts",
        "fastify.post('/signin', handler)",
        "await fastify.register(import('@fastify/rate-limit'))",
    ),
    (
        "Flask",
        "app.py",
        "@app.route('/login', methods=['POST'])\ndef login(): ...",
        "from flask_limiter import Limiter",
    ),
    (
        "FastAPI",
        "main.py",
        "@router.post('/token')\nasync def token(): ...",
        "from slowapi import Limiter",
    ),
    (
        "Django",
        "accounts/urls.py",
        "urlpatterns = [path('login/', views.login)]",
        "REST_FRAMEWORK = {'DEFAULT_THROTTLE_CLASSES': ['rest_framework.throttling.AnonRateThrottle']}",
    ),
    (
        "aiohttp",
        "server.py",
        "app.router.add_post('/login', login)",
        "from aiohttp_ratelimit import rate_limit",
    ),
    (
        "Spring",
        "src/main/java/AuthController.java",
        '@RestController\n@RequestMapping("/api/auth")\nclass A {\n  @PostMapping("/login")\n  Token login() { return null; }\n}',
        "import io.github.bucket4j.Bucket;",
    ),
    (
        "JAX-RS",
        "src/main/java/Login.java",
        '@Path("/login")\npublic class Login {}',
        "import io.github.resilience4j.ratelimiter.RateLimiter;",
    ),
    (
        "Kotlin Ktor",
        "src/main/kotlin/Routes.kt",
        'routing {\n    post("/login") {\n        call.respond(ok)\n    }\n}',
        "install(RateLimit) { register { rateLimiter(limit = 5) } }",
    ),
    (
        "Laravel",
        "routes/api.php",
        "Route::post('/login', [AuthController::class, 'login']);",
        "Route::middleware('throttle:login')->group(fn () => null);",
    ),
    (
        "Symfony",
        "src/Controller/SecurityController.php",
        "#[Route('/login', name: 'app_login', methods: ['POST'])]\npublic function login() {}",
        "use Symfony\\Component\\RateLimiter\\RateLimiterFactory;",
    ),
    (
        "Slim",
        "public/index.php",
        "$app->post('/login', LoginAction::class);",
        "$limiter = new RateLimiter($storage);",
    ),
    (
        "Rails",
        "config/routes.rb",
        "Rails.application.routes.draw do\n  post 'login', to: 'sessions#create'\nend",
        "Rack::Attack.throttle('logins/ip', limit: 5, period: 20.seconds)",
    ),
    ("Sinatra", "app.rb", "post '/login' do\n  authenticate\nend", "use Rack::Attack"),
    ("Go gin", "main.go", 'r.POST("/login", loginHandler)', 'import "golang.org/x/time/rate"'),
    (
        "Go net/http",
        "cmd/server/main.go",
        'http.HandleFunc("/auth/token", tokenHandler)',
        'import "github.com/didip/tollbooth"',
    ),
    (
        "Go Fiber",
        "server.go",
        'app.Post("/signin", signin)',
        'import "github.com/gofiber/fiber/v2/middleware/limiter"',
    ),
    (
        "ASP.NET controller",
        "Controllers/AuthController.cs",
        '[Route("api/auth")]\npublic class AuthController {\n  [HttpPost("login")]\n  public IActionResult Login() => Ok();\n}',
        "builder.Services.AddRateLimiter(o => {});",
    ),
    (
        "ASP.NET minimal API",
        "Program.cs",
        'app.MapPost("/login", (LoginDto d) => Results.Ok());',
        'app.MapPost("/x", h).RequireRateLimiting("fixed");',
    ),
    (
        "Rust actix",
        "src/main.rs",
        '#[post("/login")]\nasync fn login() -> impl Responder { "" }',
        "use actix_governor::Governor;",
    ),
    (
        "Rust axum",
        "src/routes.rs",
        'Router::new().route("/login", post(login))',
        "use tower_governor::GovernorLayer;",
    ),
    (
        "Elixir Phoenix",
        "lib/app_web/router.ex",
        'scope "/" do\n  post "/login", SessionController, :create\nend',
        "plug PlugAttack",
    ),
]


def _write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n")


def _rules(root: Path) -> dict[str, Severity]:
    findings, _ = abuse_control_findings(str(root))
    return {f.rule_id: f.severity for f in findings}


@pytest.mark.parametrize(("name", "file", "route", "_evidence"), APPS, ids=[a[0] for a in APPS])
def test_unprotected_login_is_flagged(
    tmp_path: Path, name: str, file: str, route: str, _evidence: str
) -> None:
    _write(tmp_path, {file: route})
    assert _rules(tmp_path) == {
        "api-rate-limit-missing": Severity.MEDIUM,
        "auth-lockout-missing": Severity.MEDIUM,
    }, name


@pytest.mark.parametrize(("name", "file", "route", "evidence"), APPS, ids=[a[0] for a in APPS])
def test_rate_limited_login_only_gets_the_lockout_review(
    tmp_path: Path, name: str, file: str, route: str, evidence: str
) -> None:
    _write(tmp_path, {file: route, "config/limits" + Path(file).suffix: evidence})
    assert _rules(tmp_path) == {"auth-lockout-missing": Severity.LOW}, name


@pytest.mark.parametrize(
    "lockout",
    [
        "user.failed_login_attempts += 1",
        "if (user.lockedUntil && user.lockedUntil > now) throw new Locked();",
        "INSTALLED_APPS = ['axes']  # django-axes",
        "use Illuminate\\Foundation\\Auth\\ThrottlesLogins;",
        'throw new LockedException("locked");',
        "await signInManager.PasswordSignInAsync(u, p, false, lockoutOnFailure: true);",
        "const limiterConsecutiveFailsByUsername = new RateLimiterRedis({ points: 10 });",
    ],
)
def test_lockout_evidence_clears_the_lockout_finding(tmp_path: Path, lockout: str) -> None:
    _write(
        tmp_path, {"src/server.js": "app.post('/login', login);", "src/auth/lockout.js": lockout}
    )
    assert "auth-lockout-missing" not in _rules(tmp_path)


def test_identity_provider_login_has_no_lockout_finding(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "src/server.js": "app.post('/auth/session', s);",
            "src/idp.js": "import { auth } from '@auth0/nextjs-auth0';",
        },
    )
    assert _rules(tmp_path) == {"api-rate-limit-missing": Severity.MEDIUM}


def test_api_without_auth_routes_gets_a_low_general_review(tmp_path: Path) -> None:
    _write(tmp_path, {"src/server.js": "app.get('/products', list);\napp.post('/orders', create);"})
    findings, meta = abuse_control_findings(str(tmp_path))
    assert [(f.rule_id, f.severity, f.confidence) for f in findings] == [
        ("api-rate-limit-missing-general", Severity.LOW, "low")
    ]
    assert meta["endpoints"] == 2


def test_tests_docs_and_examples_are_ignored(tmp_path: Path) -> None:
    # Routes in tests are not production endpoints; a limiter in tests doesn't protect production.
    _write(
        tmp_path,
        {
            "tests/test_login.py": "@app.route('/login', methods=['POST'])\ndef login(): ...",
            "examples/demo.js": "app.post('/login', h)",
            "docs/api.md": "app.post('/login', h)",
        },
    )
    assert _rules(tmp_path) == {}
    _write(
        tmp_path,
        {
            "src/app.js": "app.post('/login', h);",
            "tests/limits.test.js": "require('express-rate-limit')",
        },
    )
    assert "api-rate-limit-missing" in _rules(tmp_path)


def test_finding_points_at_the_first_sensitive_route_and_lists_the_others(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "src/routes.js": "app.get('/health', h);\napp.post('/login', a);\napp.post('/password/reset', b);\napp.post('/otp/verify', c);",
        },
    )
    findings, meta = abuse_control_findings(str(tmp_path))
    rate = next(f for f in findings if f.rule_id == "api-rate-limit-missing")
    assert (rate.file, rate.line) == ("src/routes.js", 2)
    assert "/password/reset" in rate.description and "/otp/verify" in rate.description
    assert meta["sensitive_endpoints"] == 3
    assert rate.cwe == "CWE-770"


@pytest.mark.asyncio
async def test_runs_as_a_scan_result(tmp_path: Path) -> None:
    _write(tmp_path, {"app.py": "@app.post('/login')\ndef login(): ..."})
    result = await run_abuse_control_check(str(tmp_path))
    assert result.tool == "argus-abuse-controls"
    assert {f.rule_id for f in result.findings} == {
        "api-rate-limit-missing",
        "auth-lockout-missing",
    }


@pytest.mark.parametrize(
    ("file", "code"),
    [
        ("report.py", 'total = sum(len(r.get("findings", [])) for r in results)'),  # dict lookup
        ("server.js", "const env = app.get('env');"),  # Express settings getter
        ("routes.js", "// e.g. app.post('/login', handler)"),  # comment
        ("views.py", "# path('login/', views.login)"),  # comment
        ("Util.java", 'Path p = Paths.get("/login");'),  # not a JAX-RS @Path
    ],
)
def test_code_that_only_looks_like_a_route_is_not_an_endpoint(
    tmp_path: Path, file: str, code: str
) -> None:
    _write(tmp_path, {file: code})
    findings, meta = abuse_control_findings(str(tmp_path))
    assert meta["endpoints"] == 0 and findings == []
