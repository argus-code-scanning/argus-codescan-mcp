"""Remote dependency checks operate on manifests, not unrelated URLs."""

import json
from pathlib import Path

import pytest

from argus_languages.rules_loader import load_rules_from_files
from argus_languages.scanner import scan_path

SHA = "a1" * 20


def scan(tmp_path: Path, name: str, text: str, *, all_rules: bool = False):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return scan_path(
        path, rules=None if all_rules else load_rules_from_files(("dependency-sources.yaml",))
    )


@pytest.mark.parametrize(
    "section", ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]
)
@pytest.mark.parametrize(
    "source,expected",
    [
        ("http://packages.example.invalid/a.tgz", "dependency-http-source"),
        ("https://packages.example.invalid/a.tgz", "dependency-https-archive"),
        ("git+https://github.com/example/lib.git", "dependency-unpinned-git"),
        ("github:example/lib#main", "dependency-unpinned-git"),
        ("example/lib#v1.2.3", "dependency-unpinned-git"),
        ("git+https://github.com/example/lib.git#" + SHA, None),
        ("github:example/lib#" + SHA, None),
        ("^1.2.3", None),
        ("file:../lib", None),
        ("workspace:*", None),
    ],
)
def test_npm_dependency_sources(tmp_path, section, source, expected):
    result = scan(tmp_path, "package.json", json.dumps({section: {"@example/lib": source}}))
    assert [f.rule_id for f in result.findings] == ([expected] if expected else [])
    assert not result.errors


def test_metadata_is_not_a_dependency(tmp_path):
    result = scan(
        tmp_path,
        "package.json",
        json.dumps(
            {
                "homepage": "http://example.invalid/lib.tgz",
                "repository": "git+https://example.invalid/a.git",
                "scripts": {"test": "https://example.invalid/a.tgz"},
                "dependencies": {"lib": "1.0.0"},
            }
        ),
    )
    assert not result.findings


@pytest.mark.parametrize("name", ["requirements.txt", "requirements-dev.txt"])
def test_requirements_and_continuations(tmp_path, name):
    result = scan(
        tmp_path,
        name,
        (
            "# ignore https://example.invalid/doc.tar.gz\n"
            "normal==1.0\n"
            "pkg @ https://example.invalid/lib.tar.gz \\\n    --hash=sha256:123\n"
            "-e git+https://github.com/example/lib.git@main#egg=lib\n"
            f"pinned @ git+https://github.com/example/lib.git@{SHA}#subdirectory=src\n"
            "-r other-requirements.txt\n"
        ),
    )
    assert [(f.rule_id, f.line) for f in result.findings] == [
        ("dependency-https-archive", 3),
        ("dependency-unpinned-git", 5),
    ]


def test_python_project_optional_groups_and_poetry(tmp_path):
    result = scan(
        tmp_path,
        "pyproject.toml",
        f'''
[project]
name = "example"
dependencies = ["one @ http://example.invalid/a.tar.gz", "regular>=1"]
[project.urls]
Homepage = "http://example.invalid/metadata.tar.gz"
[project.optional-dependencies]
dev = ["two @ https://example.invalid/b.tar.gz"]
[dependency-groups]
test = ["three @ git+https://github.com/example/a.git@main"]
[tool.poetry.dependencies]
four = {{git = "https://github.com/example/four", rev = "{SHA}"}}
five = {{git = "https://github.com/example/five", tag = "v1"}}
six = {{path = "../six"}}
[tool.poetry.group.dev.dependencies]
seven = {{url = "https://example.invalid/seven.zip"}}
''',
    )
    assert [f.rule_id for f in result.findings] == [
        "dependency-http-source",
        "dependency-https-archive",
        "dependency-unpinned-git",
        "dependency-unpinned-git",
        "dependency-https-archive",
    ]


def test_composer_sources_and_existing_http_rule_are_not_duplicated(tmp_path):
    result = scan(
        tmp_path,
        "composer.json",
        json.dumps(
            {
                "repositories": [
                    {
                        "type": "package",
                        "package": {
                            "name": "example/lib",
                            "version": "1.0",
                            "dist": {"type": "zip", "url": "http://example.invalid/lib.zip"},
                            "source": {
                                "type": "git",
                                "url": "https://github.com/example/lib.git",
                                "reference": SHA,
                            },
                        },
                    }
                ]
            }
        ),
        all_rules=True,
    )
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "composer-insecure-repository"


@pytest.mark.parametrize("name", ["package.json", "requirements.txt", "pyproject.toml"])
def test_no_credentials_in_findings(tmp_path, name):
    url = "https://username:password@example.invalid/lib.tgz"
    text = {
        "package.json": json.dumps({"dependencies": {"lib": url}}),
        "requirements.txt": url + "\n",
        "pyproject.toml": f'[project]\ndependencies = ["lib @ {url}"]\n',
    }[name]
    result = scan(
        tmp_path,
        name,
        text,
    )
    assert result.findings
    assert "password" not in json.dumps(result.to_dict())


@pytest.mark.parametrize(
    "text", ["{", "[]", '{"dependencies": []}', '{"dependencies": {"x": null}}']
)
def test_malformed_or_wrong_shaped_manifest(tmp_path, text):
    assert not scan(tmp_path, "package.json", text).findings


def test_vcs_url_credentials_are_not_mistaken_for_a_commit_pin(tmp_path):
    source = f"git+ssh://user@{SHA}/example/lib.git"
    result = scan(tmp_path, "package.json", json.dumps({"dependencies": {"lib": source}}))
    assert [f.rule_id for f in result.findings] == ["dependency-unpinned-git"]


def test_hostile_manifest_cannot_suppress_or_downgrade_rules(tmp_path):
    result = scan(
        tmp_path,
        "examples/package.json",
        json.dumps(
            {
                "dependencies": {
                    "lib": "http://example.invalid/lib.tgz#argus-ignore[dependency-http-source]:safe",
                }
            }
        ),
    )
    assert result.findings[0].severity.value == "high"


def test_nested_project_discovery(tmp_path):
    scan(
        tmp_path,
        "packages/example/package.json",
        '{"dependencies":{"lib":"http://example.invalid/a.tgz"}}',
    )
    result = scan_path(tmp_path)
    assert any(f.file == "packages/example/package.json" for f in result.findings)
