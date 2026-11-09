"""Exposed admin, debug and management endpoints, and Spring config discovery (issue #118)."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages import scan_directory
from argus_languages.discover import classify_file
from argus_languages.rules_loader import RULE_FILES, load_rules_from_files

RULES = {
    "spring-actuator-exposure-all",
    "spring-h2-console-enabled",
    "go-pprof-import",
    "js-apollo-introspection-playground",
    "js-express-admin-no-auth",
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
    assert "exposed-endpoints.yaml" in RULE_FILES
    rules = load_rules_from_files(("exposed-endpoints.yaml",))
    assert {r.id for r in rules} == RULES
    for rule in rules:
        assert rule.fix_guidance, f"{rule.id} needs fix_guidance"


@pytest.mark.parametrize(
    ("name", "content", "expected"),
    [
        ("application.properties", "server.port=8080\n", "spring-config"),
        ("application-prod.properties", "server.port=8080\n", "spring-config"),
        ("application.yml", "server:\n  port: 8080\n", "spring-config"),
        ("application-dev.yaml", "server:\n  port: 8080\n", "spring-config"),
        ("Application.Properties", "server.port=8080\n", "spring-config"),
        # Not Spring config
        ("messages.properties", "greeting=hello\n", None),
        ("log4j.properties", "log4j.rootLogger=INFO\n", None),
        ("config.yml", "server:\n  port: 8080\n", None),
        # A Kubernetes or Ansible file keeps its own type even when it is called application.yml
        ("application.yml", "apiVersion: v1\nkind: Pod\n", "kubernetes"),
    ],
)
def test_spring_config_files_are_discovered_as_their_own_type(
    tmp_path: Path, name: str, content: str, expected: str | None
) -> None:
    path = tmp_path / name
    path.write_text(content)
    assert classify_file(path, tmp_path, content) == expected


def test_generic_code_rules_do_not_apply_to_spring_config(tmp_path: Path) -> None:
    # The quoted secret_key line is what the generic hardcoded-password rule matches in code; in a
    # Spring config file only the rules written for it may fire.
    (tmp_path / "application.properties").write_text(
        "management.endpoints.web.exposure.include=*\n"
        'secret_key = "abcdefghijklmnop1234"\n'
        "debug=true\n"
    )
    found = {f.rule_id for f in scan_directory(tmp_path).findings}
    assert found == {"spring-actuator-exposure-all"}


@pytest.mark.parametrize(
    ("filename", "code", "rule", "severity"),
    [
        # Spring Boot Actuator
        (
            "application.properties",
            "management.endpoints.web.exposure.include=*",
            "spring-actuator-exposure-all",
            "high",
        ),
        (
            "application.properties",
            "management.endpoints.web.exposure.include = *",
            "spring-actuator-exposure-all",
            "high",
        ),
        ("application.yml", '    include: "*"', "spring-actuator-exposure-all", "high"),
        (
            "application-prod.yml",
            "      include: '*'   # expose all",
            "spring-actuator-exposure-all",
            "high",
        ),
        (
            "application.yml",
            'management.endpoints.web.exposure.include: "*"',
            "spring-actuator-exposure-all",
            "high",
        ),
        # H2 console
        (
            "application.properties",
            "spring.h2.console.enabled=true",
            "spring-h2-console-enabled",
            "medium",
        ),
        (
            "application.yml",
            "spring.h2.console.enabled: true",
            "spring-h2-console-enabled",
            "medium",
        ),
        # Go pprof
        ("main.go", '\t_ "net/http/pprof"', "go-pprof-import", "medium"),
        ("main.go", 'import _ "net/http/pprof"', "go-pprof-import", "medium"),
        # Apollo
        (
            "server.ts",
            "const server = new ApolloServer({ typeDefs, resolvers, introspection: true });",
            "js-apollo-introspection-playground",
            "medium",
        ),
        ("server.js", "  playground: true,", "js-apollo-introspection-playground", "medium"),
        # Express /admin
        ("app.ts", "app.use('/admin', adminRouter);", "js-express-admin-no-auth", "low"),
        ("app.js", 'app.use("/admin/tools", toolsRouter);', "js-express-admin-no-auth", "low"),
        (
            "app.js",
            "app.use('/admin', require('./routes/admin'));",
            "js-express-admin-no-auth",
            "low",
        ),
    ],
)
def test_exposed_endpoints_are_flagged(
    tmp_path: Path, filename: str, code: str, rule: str, severity: str
) -> None:
    found = _findings(tmp_path, filename, f"{code}\n")
    assert found.get(rule) == severity


@pytest.mark.parametrize(
    ("filename", "code"),
    [
        ("application.properties", "management.endpoints.web.exposure.include=health,info"),
        ("application.properties", "# management.endpoints.web.exposure.include=*"),
        ("application.properties", "! management.endpoints.web.exposure.include=*"),
        ("application.yml", "    include: health,info"),
        ("application.yml", '    include: ["health", "info"]'),
        ("application.yml", "    # include: '*'"),
        ("application.properties", "spring.h2.console.enabled=false"),
        ("application.properties", "# spring.h2.console.enabled=true"),
        ("main.go", '\t_ "github.com/lib/pq"'),
        ("main.go", '\t"net/http"'),
        ("main.go", '\t// _ "net/http/pprof"'),
        ("server.ts", "const s = new ApolloServer({ introspection: false });"),
        (
            "server.ts",
            "const s = new ApolloServer({ introspection: process.env.NODE_ENV !== 'production' });",
        ),
        ("server.js", "  // playground: true,"),
        ("app.ts", "app.use('/admin', requireAdmin, adminRouter);"),
        ("app.ts", "app.use('/admin', authenticate, router);"),
        ("app.ts", "app.use('/admin', passport.authenticate('jwt'), router);"),
        ("app.ts", "app.use('/api', apiRouter);"),
        ("app.ts", "app.use('/admin', express.static('admin-assets'));"),
    ],
)
def test_safe_config_and_code_is_not_flagged(tmp_path: Path, filename: str, code: str) -> None:
    assert _findings(tmp_path, filename, f"{code}\n") == {}


def test_rules_only_apply_to_their_own_file_type(tmp_path: Path) -> None:
    cases = {
        "spring_line_in_python": ("x.py", "management.endpoints.web.exposure.include=*\n"),
        "spring_line_in_readme_properties": (
            "messages.properties",
            "spring.h2.console.enabled=true\n",
        ),
        "pprof_in_js": ("x.js", '_ "net/http/pprof"\n'),
        "apollo_in_java": ("X.java", "introspection: true\n"),
    }
    for name, (filename, code) in cases.items():
        folder = tmp_path / name
        folder.mkdir()
        assert _findings(folder, filename, code) == {}, name
