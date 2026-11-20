"""Insecure cookie flags: missing or disabled HttpOnly / Secure on session and auth cookies (#197)."""  # noqa: E501

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages import scan_directory
from argus_languages.rules_loader import RULE_FILES, load_rules_from_files

COOKIE_RULES = {r.id for r in load_rules_from_files(("cookies.yaml",))}


def _rules(tmp_path: Path, filename: str, code: str) -> set[str]:
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code)
    return {f.rule_id for f in scan_directory(tmp_path).findings if f.rule_id in COOKIE_RULES}


def test_rule_pack_is_registered() -> None:
    assert "cookies.yaml" in RULE_FILES
    assert len(COOKIE_RULES) == 12
    for rule in load_rules_from_files(("cookies.yaml",)):
        assert rule.fix_guidance, f"{rule.id} needs fix_guidance"


@pytest.mark.parametrize(
    ("filename", "code", "rule"),
    [
        ("app.js", 'res.cookie("session", token);\n', "js-cookie-sensitive-no-options"),
        ("app.ts", "res.cookie('auth_token', sign(user));\n", "js-cookie-sensitive-no-options"),
        ("app.js", 'res.cookie("token", t, { httpOnly: false });\n', "js-cookie-httponly-disabled"),
        (
            "app.js",
            "app.use(session({ secret, cookie: { secure: false } }));\n",
            "js-cookie-secure-disabled",
        ),
        ("views.py", 'resp.set_cookie("session", sid)\n', "python-cookie-sensitive-no-options"),
        (
            "views.py",
            'resp.set_cookie("sid", sid, secure=False, httponly=True)\n',
            "python-cookie-flag-disabled",
        ),
        (
            "settings.py",
            "SESSION_COOKIE_SECURE = False\n",
            "python-session-cookie-settings-insecure",
        ),
        (
            "app.py",
            'app.config["SESSION_COOKIE_HTTPONLY"] = False\n',
            "python-session-cookie-settings-insecure",
        ),
        ("settings.py", "CSRF_COOKIE_SECURE = False\n", "python-session-cookie-settings-insecure"),
        (
            "Login.java",
            'Cookie c = new Cookie("JSESSIONID", id);\nc.setPath("/");\nresponse.addCookie(c);\n',
            "java-cookie-without-httponly",
        ),
        ("Login.java", "cookie.setHttpOnly(false);\n", "java-cookie-flag-disabled"),
        (
            "application.properties",
            "server.servlet.session.cookie.secure=false\n",
            "spring-session-cookie-insecure",
        ),
        (
            "application.yml",
            "server.servlet.session.cookie.http-only: false\n",
            "spring-session-cookie-insecure",
        ),
        ("login.php", '<?php setcookie("session", $id);\n', "php-setcookie-sensitive-no-options"),
        (
            "login.php",
            '<?php setcookie("sid", $id, ["httponly" => false]);\n',
            "php-cookie-flag-disabled",
        ),
        ("boot.php", "<?php ini_set('session.cookie_secure', 0);\n", "php-cookie-flag-disabled"),
        (
            "Startup.cs",
            "var o = new CookieOptions { HttpOnly = false, Secure = true };\n",
            "csharp-cookie-flag-disabled",
        ),
        (
            "Startup.cs",
            "options.Secure = CookieSecurePolicy.None;\n",
            "csharp-cookie-flag-disabled",
        ),
    ],
)
def test_flags_insecure_cookies(tmp_path: Path, filename: str, code: str, rule: str) -> None:
    assert rule in _rules(tmp_path, filename, code)


@pytest.mark.parametrize(
    ("filename", "code"),
    [
        # options present, or not a session/auth cookie
        (
            "app.js",
            'res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "lax" });\n',
        ),
        ("app.js", 'res.cookie("session", token, {\n  httpOnly: true,\n});\n'),
        ("app.js", 'res.cookie("theme", "dark");\n'),
        ("app.js", "res.cookie(name, value, cookieOptions);\n"),
        # SMTP / TLS "secure: false" is not a cookie setting
        ("mail.js", "nodemailer.createTransport({ host, port: 587, secure: false });\n"),
        (
            "views.py",
            'resp.set_cookie("session", sid, secure=True, httponly=True, samesite="Lax")\n',
        ),
        ("views.py", 'resp.set_cookie("lang", "en")\n'),
        ("settings.py", "SESSION_COOKIE_SECURE = True\n"),
        (
            "Login.java",
            'Cookie c = new Cookie("JSESSIONID", id);\nc.setHttpOnly(true);\nc.setSecure(true);\nresponse.addCookie(c);\n',  # noqa: E501
        ),
        ("Prefs.java", 'Cookie c = new Cookie("theme", t);\nresponse.addCookie(c);\n'),
        ("application.properties", "server.servlet.session.cookie.secure=true\n"),
        ("login.php", '<?php setcookie("session", $id, ["secure" => true, "httponly" => true]);\n'),
        ("Startup.cs", "var o = new CookieOptions { HttpOnly = true, Secure = true };\n"),
    ],
)
def test_safe_cookies_not_flagged(tmp_path: Path, filename: str, code: str) -> None:
    assert _rules(tmp_path, filename, code) == set()
