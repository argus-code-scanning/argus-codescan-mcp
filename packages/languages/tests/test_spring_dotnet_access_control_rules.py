"""Spring Security, JSR-250 and ASP.NET Core access-control rules (issue #115)."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages import scan_directory

RULES = {
    "java-spring-permitall-everything",
    "java-spring-web-ignoring-everything",
    "java-jsr250-permitall",
    "dotnet-allowanonymous-attribute",
    "dotnet-allowanonymous-endpoint",
}


def _findings(tmp_path: Path, filename: str, code: str) -> dict[str, str]:
    path = tmp_path / filename
    path.write_text(code)
    return {
        f.rule_id: str(f.severity.value)
        for f in scan_directory(tmp_path).findings
        if f.rule_id in RULES
    }


@pytest.mark.parametrize(
    ("filename", "code", "rule", "severity"),
    [
        # Spring Security: permit everything
        (
            "SecurityConfig.java",
            "http.authorizeHttpRequests(a -> a.anyRequest().permitAll());",
            "java-spring-permitall-everything",
            "high",
        ),
        (
            "SecurityConfig.java",
            '.authorizeHttpRequests(a -> a.requestMatchers("/**").permitAll())',
            "java-spring-permitall-everything",
            "high",
        ),
        (
            "SecurityConfig.java",
            '.authorizeRequests().antMatchers("/**").permitAll();',
            "java-spring-permitall-everything",
            "high",
        ),
        (
            "SecurityConfig.kt",
            "authorize(anyRequest, permitAll)",
            "java-spring-permitall-everything",
            "high",
        ),
        (
            "SecurityConfig.kt",
            "http.authorizeHttpRequests { it.anyRequest().permitAll() }",
            "java-spring-permitall-everything",
            "high",
        ),
        # Spring Security: ignore everything
        (
            "SecurityConfig.java",
            "return web -> web.ignoring().anyRequest();",
            "java-spring-web-ignoring-everything",
            "high",
        ),
        (
            "SecurityConfig.java",
            'return web -> web.ignoring().requestMatchers("/**");',
            "java-spring-web-ignoring-everything",
            "high",
        ),
        # JSR-250
        ("UserController.java", "@PermitAll", "java-jsr250-permitall", "medium"),
        (
            "UserController.java",
            '@PermitAll @GetMapping("/health") public String health() { return "ok"; }',
            "java-jsr250-permitall",
            "medium",
        ),
        ("UserController.kt", "    @PermitAll", "java-jsr250-permitall", "medium"),
        # ASP.NET Core
        ("UsersController.cs", "[AllowAnonymous]", "dotnet-allowanonymous-attribute", "medium"),
        (
            "UsersController.cs",
            "    [HttpGet, AllowAnonymous]",
            "dotnet-allowanonymous-attribute",
            "medium",
        ),
        (
            "Program.cs",
            'app.MapGet("/ping", () => "pong").AllowAnonymous();',
            "dotnet-allowanonymous-endpoint",
            "medium",
        ),
    ],
)
def test_vulnerable_code_is_flagged(
    tmp_path: Path, filename: str, code: str, rule: str, severity: str
) -> None:
    found = _findings(tmp_path, filename, f"{code}\n")
    assert rule in found
    assert found[rule] == severity


@pytest.mark.parametrize(
    ("filename", "code"),
    [
        ("SecurityConfig.java", "http.authorizeHttpRequests(a -> a.anyRequest().authenticated());"),
        (
            "SecurityConfig.java",
            '.authorizeHttpRequests(a -> a.requestMatchers("/public/**").permitAll())',
        ),
        (
            "SecurityConfig.java",
            '.authorizeHttpRequests(a -> a.requestMatchers("/api/**").permitAll())',
        ),
        (
            "SecurityConfig.java",
            'return web -> web.ignoring().requestMatchers("/css/**", "/images/**");',
        ),
        ("SecurityConfig.kt", "authorize(anyRequest, authenticated)"),
        ("UserController.java", '@RolesAllowed("ADMIN")'),
        ("UserController.java", "@PreAuthorize(\"hasRole('ADMIN')\")"),
        ("UserController.java", "import jakarta.annotation.security.PermitAll;"),
        ("UserController.java", "// @PermitAll was removed from this endpoint"),
        ("UsersController.cs", "[Authorize]"),
        ("UsersController.cs", "// [AllowAnonymous] was removed"),
        ("UsersController.cs", "using Microsoft.AspNetCore.Authorization;"),
        ("Program.cs", 'app.MapGet("/orders", () => "ok").RequireAuthorization();'),
    ],
)
def test_safe_code_is_not_flagged(tmp_path: Path, filename: str, code: str) -> None:
    assert _findings(tmp_path, filename, f"{code}\n") == {}


def test_rules_only_apply_to_their_own_language(tmp_path: Path) -> None:
    cases = {
        "java_in_python": ("views.py", "@PermitAll\n"),
        "dotnet_in_java": ("Main.java", "[AllowAnonymous]\n"),
        "spring_in_csharp": ("Program.cs", "http.anyRequest().permitAll();\n"),
        "text_file": ("notes.txt", "@PermitAll\n[AllowAnonymous]\n"),
    }
    for name, (filename, code) in cases.items():
        folder = tmp_path / name
        folder.mkdir()
        assert _findings(folder, filename, code) == {}, name
