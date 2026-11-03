"""Rails, Laravel, Express and NestJS access-control opt-outs (issue #116)."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages import scan_directory
from argus_languages.rules_loader import RULE_FILES, load_rules_from_files

RULES = {
    "ruby-rails-skip-authentication",
    "ruby-rails-skip-authentication-some-actions",
    "ruby-rails-skip-csrf",
    "ruby-rails-csrf-null-session",
    "php-laravel-without-auth-middleware",
    "js-express-cors-reflect-origin-credentials",
    "js-nestjs-public-decorator",
}


def _findings(tmp_path: Path, filename: str, code: str) -> dict[str, str]:
    path = tmp_path / filename
    path.write_text(code)
    return {
        f.rule_id: str(f.severity.value)
        for f in scan_directory(tmp_path).findings
        if f.rule_id in RULES
    }


def test_rule_pack_is_registered_and_complete() -> None:
    assert "access-control-web.yaml" in RULE_FILES
    rules = load_rules_from_files(("access-control-web.yaml",))
    assert {r.id for r in rules} == RULES
    for rule in rules:
        assert rule.fix_guidance, f"{rule.id} needs fix_guidance"


@pytest.mark.parametrize(
    ("filename", "code", "expected"),
    [
        # Rails / Devise: no only:/except: is high, with them it is a "review" finding
        (
            "users_controller.rb",
            "  skip_before_action :authenticate_user!",
            {"ruby-rails-skip-authentication": "high"},
        ),
        (
            "users_controller.rb",
            "  skip_before_filter :authenticate_user!",
            {"ruby-rails-skip-authentication": "high"},
        ),
        (
            "users_controller.rb",
            "  skip_before_action :authenticate_user!, only: [:index, :show]",
            {"ruby-rails-skip-authentication-some-actions": "medium"},
        ),
        (
            "users_controller.rb",
            "  skip_before_action :authenticate_admin!, except: :create",
            {"ruby-rails-skip-authentication-some-actions": "medium"},
        ),
        (
            "hooks_controller.rb",
            "  skip_before_action :verify_authenticity_token",
            {"ruby-rails-skip-csrf": "medium"},
        ),
        (
            "hooks_controller.rb",
            "  skip_before_action :verify_authenticity_token, only: [:webhook]",
            {"ruby-rails-skip-csrf": "medium"},
        ),
        (
            "base_controller.rb",
            "  protect_from_forgery with: :null_session",
            {"ruby-rails-csrf-null-session": "low"},
        ),
        # Laravel
        (
            "routes.php",
            "Route::get('/status', [StatusController::class, 'show'])->withoutMiddleware('auth');",
            {"php-laravel-without-auth-middleware": "high"},
        ),
        (
            "routes.php",
            "Route::post('/hook', HookController::class)->withoutMiddleware(['auth', 'verified']);",
            {"php-laravel-without-auth-middleware": "high"},
        ),
        (
            "routes.php",
            'Route::get("/me", MeController::class)->withoutMiddleware("auth:sanctum");',
            {"php-laravel-without-auth-middleware": "high"},
        ),
        # Express cors
        (
            "server.js",
            "app.use(cors({ origin: true, credentials: true }));",
            {"js-express-cors-reflect-origin-credentials": "high"},
        ),
        (
            "server.ts",
            "app.use(cors({ credentials: true, origin: true }));",
            {"js-express-cors-reflect-origin-credentials": "high"},
        ),
        # NestJS
        ("users.controller.ts", "  @Public()", {"js-nestjs-public-decorator": "low"}),
        (
            "auth.controller.ts",
            "  @SkipAuth() @Get('health') health() { return 'ok'; }",
            {"js-nestjs-public-decorator": "low"},
        ),
    ],
)
def test_vulnerable_code_is_flagged(
    tmp_path: Path, filename: str, code: str, expected: dict[str, str]
) -> None:
    assert _findings(tmp_path, filename, f"{code}\n") == expected


@pytest.mark.parametrize(
    ("filename", "code"),
    [
        ("users_controller.rb", "  before_action :authenticate_user!"),
        ("users_controller.rb", "  skip_before_action :set_locale"),
        ("users_controller.rb", "  # skip_before_action :authenticate_user!"),
        ("users_controller.rb", "  # skip_before_action :verify_authenticity_token"),
        ("base_controller.rb", "  protect_from_forgery with: :exception"),
        ("base_controller.rb", "  # protect_from_forgery with: :null_session"),
        ("routes.php", "Route::get('/me', MeController::class)->middleware('auth');"),
        ("routes.php", "Route::get('/x', XController::class)->withoutMiddleware('throttle');"),
        (
            "routes.php",
            "Route::get('/x', XController::class)->withoutMiddleware(['throttle:api']);",
        ),
        ("routes.php", "// ->withoutMiddleware('auth') was removed"),
        (
            "server.js",
            "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));",
        ),
        ("server.js", "app.use(cors({ origin: true }));"),
        ("server.js", "app.use(cors({ origin: true, credentials: false }));"),
        ("server.js", "// app.use(cors({ origin: true, credentials: true }));"),
        ("users.controller.ts", "  @UseGuards(AuthGuard)"),
        ("users.controller.ts", "import { Public } from './public.decorator';"),
        ("users.controller.ts", "  // @Public() was removed"),
        ("users.controller.ts", "  @PublicKey()"),
    ],
)
def test_safe_code_is_not_flagged(tmp_path: Path, filename: str, code: str) -> None:
    assert _findings(tmp_path, filename, f"{code}\n") == {}


def test_rules_only_apply_to_their_own_language(tmp_path: Path) -> None:
    cases = {
        "rails_in_python": ("views.py", "skip_before_action :authenticate_user!\n"),
        "laravel_in_ruby": ("routes.rb", "->withoutMiddleware('auth')\n"),
        "cors_in_php": ("server.php", "cors({ origin: true, credentials: true })\n"),
        "nest_in_java": ("Users.java", "@Public()\n"),
        "text_file": ("notes.txt", "skip_before_action :authenticate_user!\n@Public()\n"),
    }
    for name, (filename, code) in cases.items():
        folder = tmp_path / name
        folder.mkdir()
        assert _findings(folder, filename, code) == {}, name
