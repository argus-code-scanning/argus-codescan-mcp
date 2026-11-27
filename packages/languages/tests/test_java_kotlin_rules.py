"""Java / Kotlin / Spring / Android rules (java.yaml)."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages.rules_loader import load_rules_from_files
from argus_languages.scanner import scan_directory

RULES = {r.id: r for r in load_rules_from_files(("java.yaml",))}


def hits(text: str) -> set[str]:
    return {rid for rid, r in RULES.items() if r.pattern.search(text)}


def test_new_rules_have_fix_guidance() -> None:
    old = {
        "java-sql-statement-concat",
        "java-ldap-injection",
        "java-path-traversal",
        "spring-csrf-disabled",
        "java-log-injection",
    }
    assert all(r.fix_guidance for rid, r in RULES.items() if rid not in old)


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();", "java-xxe"),
        ("val tf = TransformerFactory.newInstance()", "java-xxe"),
        ("SAXReader reader = new SAXReader();", "java-xxe"),
        ("Expression e = parser.parseExpression(userInput);", "java-spel-injection"),
        ("val e = SpelExpressionParser().parseExpression(expr)", "java-spel-injection"),
        (
            "Object v = Ognl.getValue(expression, context, root);",
            "java-expression-language-injection",
        ),
        ("MVEL.eval(rule, vars);", "java-expression-language-injection"),
        (
            "ValueExpression ve = factory.createValueExpression(ctx, userExpr, Object.class);",
            "java-expression-language-injection",
        ),
        ("Object r = engine.eval(script);", "java-script-engine-eval"),
        ("val r = GroovyShell().evaluate(code)", "java-script-engine-eval"),
        ('Class<?> c = Class.forName(request.getParameter("type"));', "java-unsafe-reflection"),
        ("mapper.enableDefaultTyping();", "java-jackson-default-typing"),
        ("@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)", "java-jackson-default-typing"),
        ("XStream xs = new XStream();", "java-xstream-unrestricted"),
        ("Yaml yaml = new Yaml();", "java-snakeyaml-unsafe"),
        ('Cipher c = Cipher.getInstance("AES");', "java-cipher-weak-mode"),
        ('val c = Cipher.getInstance("AES/ECB/PKCS5Padding")', "java-cipher-weak-mode"),
        ('Cipher c = Cipher.getInstance("DES");', "java-cipher-weak-mode"),
        ("IvParameterSpec iv = new IvParameterSpec(new byte[16]);", "java-static-iv"),
        ('val iv = IvParameterSpec("0123456789abcdef".toByteArray())', "java-static-iv"),
        ("val xs = XStream()", "java-xstream-unrestricted"),
        ("val yaml = Yaml()", "java-snakeyaml-unsafe"),
        ("val out = File(destDir, entry.name)", "java-zip-slip"),
        ("@CrossOrigin", "spring-cors-any-origin"),
        ('@CrossOrigin(origins = "*")', "spring-cors-any-origin"),
        ('registry.addMapping("/**").allowedOrigins("*")', "spring-cors-any-origin"),
        ("File out = new File(destDir, entry.getName());", "java-zip-slip"),
        ("val out = target.resolve(entry.name)", "java-zip-slip"),
        ('webView.addJavascriptInterface(bridge, "Android")', "android-webview-js-bridge"),
        ("settings.setAllowUniversalAccessFromFileURLs(true);", "android-webview-file-access"),
        ("settings.allowFileAccessFromFileURLs = true", "android-webview-file-access"),
        ('openFileOutput("x", Context.MODE_WORLD_READABLE)', "android-world-readable-file"),
    ],
)
def test_flags(text: str, rule: str) -> None:
    assert rule in hits(text)


@pytest.mark.parametrize(
    "text",
    [
        'Expression e = parser.parseExpression("#root.name");',
        'Ognl.getValue("name", context, root);',
        'Object r = engine.eval("1 + 1");',
        "Class<?> c = Class.forName(HANDLERS.get(name));",
        "mapper.findAndRegisterModules();",
        "@JsonTypeInfo(use = JsonTypeInfo.Id.NAME)",
        "Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));",
        'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");',
        "IvParameterSpec iv = new IvParameterSpec(ivBytes);",
        "GCMParameterSpec spec = new GCMParameterSpec(128, nonce);",
        '@CrossOrigin(origins = "https://app.example.com")',
        'registry.addMapping("/**").allowedOrigins("https://app.example.com")',
        "File out = new File(destDir, safeName);",
        "settings.setAllowUniversalAccessFromFileURLs(false);",
        'openFileOutput("x", Context.MODE_PRIVATE)',
    ],
)
def test_does_not_flag(text: str) -> None:
    assert not hits(text)


def _scan(tmp_path: Path, files: dict[str, str]) -> list[tuple[str, int, str]]:
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    return sorted((f.rule_id, f.line, f.confidence) for f in scan_directory(tmp_path).findings)


def test_secured_xml_parser_is_low_confidence(tmp_path: Path) -> None:
    found = _scan(
        tmp_path,
        {
            "Safe.java": "class Safe {\n  void p() {\n"
            "    var f = DocumentBuilderFactory.newInstance();\n"
            '    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
            "  }\n}\n",
            "Open.java": "class Open {\n  void p() {\n"
            "    var f = DocumentBuilderFactory.newInstance();\n  }\n}\n",
        },
    )
    xxe = [(line, conf) for rule, line, conf in found if rule == "java-xxe"]
    assert sorted(xxe) == [(3, "low"), (3, "medium")]


def test_xstream_with_allow_list_is_low_confidence(tmp_path: Path) -> None:
    found = _scan(
        tmp_path,
        {
            "X.java": "class X {\n  XStream x = new XStream();\n"
            "  { x.addPermission(NoTypePermission.NONE);\n"
            "    x.allowTypes(new Class[]{Order.class}); }\n}\n"
        },
    )
    assert ("java-xstream-unrestricted", 2, "low") in found


def test_spring_config_secrets(tmp_path: Path) -> None:
    found = _scan(
        tmp_path,
        {
            "src/main/resources/application.properties": (
                "spring.datasource.url=jdbc:postgresql://db/app\n"
                "spring.datasource.password=Sup3rS3cret\n"
                "app.jwt.secret=${JWT_SECRET}\n"
                "spring.mail.password=ENC(abc123)\n"
            ),
            "src/main/resources/application-prod.yml": (
                "spring:\n  datasource:\n    password: realPassw0rd\n"
                "app:\n  jwt-secret: ${JWT_SECRET}\n"
            ),
        },
    )
    secrets = sorted(line for rule, line, _ in found if rule == "spring-config-plaintext-secret")
    assert secrets == [2, 3]


def test_kotlin_file_end_to_end(tmp_path: Path) -> None:
    found = _scan(
        tmp_path,
        {
            "app/src/main/java/com/x/Web.kt": (
                "class Web {\n"
                "  fun setup(v: WebView) {\n"
                "    v.settings.allowUniversalAccessFromFileURLs = true\n"
                '    v.addJavascriptInterface(Bridge(), "app")\n'
                "  }\n"
                "}\n"
            )
        },
    )
    rules = {rule for rule, _, _ in found}
    assert {"android-webview-file-access", "android-webview-js-bridge"} <= rules
