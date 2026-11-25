"""XPath queries built from user input (issue #186): evaluation calls with an XPath
shape (// axis plus predicate) built through interpolation, formatting or concatenation."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages import scan_directory

XPATH_RULES = {
    "python-xpath-string-build",
    "js-xpath-string-build",
    "java-xpath-string-build",
    "php-xpath-string-build",
    "csharp-xpath-string-build",
}


def _findings(tmp_path: Path, filename: str, code: str) -> set[str]:
    path = tmp_path / filename
    path.write_text(code)
    return {f.rule_id for f in scan_directory(tmp_path).findings if f.rule_id in XPATH_RULES}


@pytest.mark.parametrize(
    ("filename", "code", "rule"),
    [
        # Python — lxml xpath()
        (
            "app.py",
            "nodes = tree.xpath(f\"//user[name='{name}']\")",
            "python-xpath-string-build",
        ),
        (
            "app.py",
            "nodes = tree.xpath(\"//user[name='\" + name + \"']\")",
            "python-xpath-string-build",
        ),
        # Python — ElementTree findall()
        (
            "app.py",
            "nodes = root.findall(\".//user[@name='\" + name + \"']\")",
            "python-xpath-string-build",
        ),
        (
            "app.py",
            "nodes = root.findall(f\".//user[@id={uid}]\")",
            "python-xpath-string-build",
        ),
        # JavaScript / TypeScript — xpath.select()
        (
            "app.js",
            "const nodes = xpath.select(\"//user[name='\" + req.query.name + \"']\", doc);",
            "js-xpath-string-build",
        ),
        (
            "app.ts",
            "const nodes = xpath.select(`//user[name='${name}']`, doc);",
            "js-xpath-string-build",
        ),
        # JavaScript — browser document.evaluate()
        (
            "app.js",
            "const node = document.evaluate(`//item[@id='${id}']`, document, null, 9, null);",
            "js-xpath-string-build",
        ),
        # Java — javax.xml.xpath evaluate()
        (
            "App.java",
            "String value = xpath.evaluate(\"//user[name='\" + username + \"']\", doc);",
            "java-xpath-string-build",
        ),
        (
            "App.java",
            "String value = xpath.evaluate(String.format(\"//user[name='%s']\", username), doc);",
            "java-xpath-string-build",
        ),
        # PHP — DOMXPath::query()
        (
            "app.php",
            "$nodes = $xpath->query(\"//user[name='\" . $_GET['name'] . \"']\");",
            "php-xpath-string-build",
        ),
        (
            "app.php",
            "$nodes = $xpath->query(\"//user[name='$name']\");",
            "php-xpath-string-build",
        ),
        # C# — SelectNodes / SelectSingleNode
        (
            "App.cs",
            "var node = doc.SelectSingleNode(\"//user[name='\" + name + \"']\");",
            "csharp-xpath-string-build",
        ),
        (
            "App.cs",
            "var nodes = doc.SelectNodes($\"//user[@id='{id}']\");",
            "csharp-xpath-string-build",
        ),
    ],
)
def test_xpath_query_built_from_input_is_flagged(
    tmp_path: Path, filename: str, code: str, rule: str
) -> None:
    assert _findings(tmp_path, filename, code) == {rule}


@pytest.mark.parametrize(
    ("filename", "code"),
    [
        # lxml named parameters — the safe pattern
        ("app.py", 'nodes = tree.xpath("//user[name=$n]", n=name)'),
        # constant query — nothing user-controlled
        ("app.py", "nodes = tree.xpath(\"//user[name='admin']\")"),
        ("app.py", "nodes = root.findall(\".//user[@name='admin']\")"),
        # xpath npm variables
        ("app.js", "const nodes = xpath.select('//user[name=$name]', doc, { name });"),
        ("app.js", "const node = document.evaluate('//item[@id=\"x\"]', document, null, 9, null);"),
        # Java: compile + XPathVariableResolver, no concat on the evaluate line
        ("App.java", 'String value = xpath.evaluate("//user[name=$n]", doc, resolver);'),
        ("App.java", 'String value = xpath.evaluate("//user[name=\'admin\']", doc);'),
        # PHP: constant query
        ("app.php", "$nodes = $xpath->query(\"//user[name='admin']\");"),
        # C#: compiled expression with variables
        ("App.cs", 'var node = doc.SelectSingleNode("//user[name=\'admin\']");'),
        # unrelated calls that merely look similar
        ("app.js", "const rows = db.select(`// ordered by ${id}`);"),
        ("app.py", "value = obj.evaluate(first + second)"),
    ],
)
def test_parameterised_or_constant_xpath_is_not_flagged(
    tmp_path: Path, filename: str, code: str
) -> None:
    assert _findings(tmp_path, filename, code) == set()
