"""Missing / disabled HTTP security headers (#198)."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.models import Severity
from argus.tools.security_headers import run_security_headers_check, security_header_findings


def _write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def _rules(root: Path) -> dict[str, Severity]:
    findings, _ = security_header_findings(str(root))
    return {f.rule_id: f.severity for f in findings}


# (framework, files without headers, evidence that fixes it)
APPS = [
    (
        "Express",
        {"package.json": '{"dependencies": {"express": "^4"}}', "src/app.js": "app.get('/', h);"},
        {"src/sec.js": "app.use(require('helmet')());"},
    ),
    (
        "NestJS",
        {"package.json": '{"dependencies": {"@nestjs/core": "^10"}}', "src/main.ts": "x"},
        {"src/main.ts": "import helmet from 'helmet';"},
    ),
    (
        "Next.js",
        {"package.json": '{"dependencies": {"next": "15"}}', "app/page.tsx": "export default 1"},
        {
            "next.config.js": "headers: [{ key: 'Content-Security-Policy', value: \"default-src 'self'\" }]"
        },
    ),
    (
        "Django",
        {"requirements.txt": "Django==5.0\n", "app/views.py": "x = 1"},
        {"app/settings.py": "SECURE_HSTS_SECONDS = 31536000\n"},
    ),
    (
        "Flask",
        {"requirements.txt": "flask>=3\n", "app.py": "@app.route('/')\ndef i(): pass"},
        {"app.py": "from flask_talisman import Talisman\nTalisman(app)"},
    ),
    (
        "Spring Boot",
        {"pom.xml": "<artifactId>spring-boot-starter-web</artifactId>"},
        {
            "pom.xml": "<artifactId>spring-boot-starter-web</artifactId><artifactId>spring-boot-starter-security</artifactId>"
        },  # noqa: E501
    ),
    (
        "Laravel",
        {"composer.json": '{"require": {"laravel/framework": "^11"}}'},
        {"composer.json": '{"require": {"laravel/framework": "^11", "spatie/laravel-csp": "^2"}}'},
    ),
    (
        "Rails",
        {"Gemfile": "gem 'rails', '~> 7.1'\n"},
        {
            "config/initializers/csp.rb": "Rails.application.configure { config.content_security_policy {} }"
        },  # noqa: E501
    ),
    (
        "ASP.NET Core",
        {"Api.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>'},
        {"Program.cs": "app.UseHsts();"},
    ),
    (
        "Go",
        {"go.mod": "require github.com/gin-gonic/gin v1.9.0\n", "main.go": 'r.GET("/", h)'},
        {"main.go": 'r.GET("/", h)\nimport "github.com/unrolled/secure"'},
    ),
    (
        "nginx in front",
        {"package.json": '{"dependencies": {"express": "^4"}}'},
        {"deploy/nginx.conf": 'add_header Strict-Transport-Security "max-age=31536000" always;'},
    ),
]


@pytest.mark.parametrize(("name", "app", "fix"), APPS, ids=[a[0] for a in APPS])
def test_missing_headers_flagged_until_evidence_added(
    tmp_path: Path, name: str, app: dict[str, str], fix: dict[str, str]
) -> None:
    _write(tmp_path, app)
    assert "security-headers-missing" in _rules(tmp_path), name
    _write(tmp_path, fix)
    assert "security-headers-missing" not in _rules(tmp_path), name


def test_page_apps_medium_api_only_low(tmp_path: Path) -> None:
    _write(tmp_path / "web", {"package.json": '{"dependencies": {"next": "15"}}'})
    _write(tmp_path / "api", {"package.json": '{"dependencies": {"fastify": "^4"}}'})
    assert _rules(tmp_path / "web")["security-headers-missing"] == Severity.MEDIUM
    assert _rules(tmp_path / "api")["security-headers-missing"] == Severity.LOW


def test_not_a_web_app_is_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path, {"package.json": '{"dependencies": {"commander": "^12"}}', "cli.js": "x"})
    assert _rules(tmp_path) == {}


def test_evidence_in_tests_does_not_count(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "package.json": '{"dependencies": {"express": "^4"}}',
            "tests/app.test.js": "app.use(helmet())",
        },
    )
    assert "security-headers-missing" in _rules(tmp_path)


@pytest.mark.parametrize(
    ("file", "code", "rule", "severity"),
    [
        ("src/Sec.java", "http.headers().disable();", "security-headers-disabled", Severity.HIGH),
        (
            "src/Sec.java",
            "http.headers(h -> h.disable());",
            "security-headers-disabled",
            Severity.HIGH,
        ),
        (
            "src/Sec.java",
            "http.headers(AbstractHttpConfigurer::disable);",
            "security-headers-disabled",
            Severity.HIGH,
        ),
        (
            "deploy/nginx.conf",
            "add_header X-Frame-Options ALLOWALL;",
            "x-frame-options-allowall",
            Severity.HIGH,
        ),  # noqa: E501
        (
            "src/app.js",
            "app.use(helmet({ contentSecurityPolicy: false }));",
            "helmet-protection-disabled",
            Severity.MEDIUM,
        ),  # noqa: E501
        ("app/settings.py", "SECURE_HSTS_SECONDS = 0\n", "django-hsts-disabled", Severity.MEDIUM),
    ],
)
def test_explicit_downgrades(
    tmp_path: Path, file: str, code: str, rule: str, severity: Severity
) -> None:
    _write(tmp_path, {file: code})
    rules = _rules(tmp_path)
    assert rules.get(rule) == severity


def test_fix_guidance_names_the_framework(tmp_path: Path) -> None:
    _write(tmp_path, {"package.json": '{"dependencies": {"express": "^4"}}'})
    findings, meta = security_header_findings(str(tmp_path))
    assert meta["frameworks"] == ["Express"]
    assert "helmet" in findings[0].fix_guidance
    assert findings[0].file == "package.json"


@pytest.mark.asyncio
async def test_runs_as_a_scan_result(tmp_path: Path) -> None:
    _write(tmp_path, {"package.json": '{"dependencies": {"express": "^4"}}'})
    result = await run_security_headers_check(str(tmp_path))
    assert result.tool == "argus-security-headers"
    assert [f.rule_id for f in result.findings] == ["security-headers-missing"]
