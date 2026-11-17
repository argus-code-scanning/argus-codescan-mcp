"""Dependency vulnerabilities for every ecosystem via OSV: lockfile readers, install paths,
dev-only handling, per-package grouping and fix advice. OSV is mocked; nothing goes online."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from argus.models import Severity
from argus.tools import malicious_packages as mp
from argus.tools import osv_deps
from argus.tools.dep_graph import read_graph
from argus.tools.malicious_packages import Package

GO_MOD = """module example.com/svc

go 1.22

toolchain go1.22.1

require github.com/gin-gonic/gin v1.9.0

require (
\tgolang.org/x/net v0.7.0 // indirect
\tgithub.com/pkg/errors v0.9.1+incompatible
)

replace (
\texample.com/old v1.0.0 => example.com/new v1.1.0
)
"""

PUBSPEC_LOCK = """packages:
  http:
    dependency: "direct main"
    source: hosted
    version: "0.13.2"
  mocktail:
    dependency: "direct dev"
    source: hosted
    version: "1.0.0"
  meta:
    dependency: transitive
    source: hosted
    version: "1.9.1"
  flutter:
    dependency: "direct main"
    source: sdk
    version: "0.0.0"
"""

CARGO_LOCK = """version = 3

[[package]]
name = "cli"
version = "0.1.0"
dependencies = ["chrono"]

[[package]]
name = "chrono"
version = "0.4.19"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["time"]

[[package]]
name = "time"
version = "0.1.43"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""

GEMFILE_LOCK = """GEM
  remote: https://rubygems.org/
  specs:
    loofah (2.19.0)
      nokogiri (>= 1.5.9)
    nokogiri (1.13.0-x86_64-linux)
      racc (~> 1.4)
    racc (1.6.0)

DEPENDENCIES
  loofah
"""

NUGET_LOCK = {
    "version": 1,
    "dependencies": {
        "net8.0": {
            "Newtonsoft.Json": {"type": "Direct", "resolved": "12.0.1"},
            "Html.Abstractions": {
                "type": "Direct",
                "resolved": "2.1.0",
                "dependencies": {"System.Text.Encodings.Web": "4.5.0"},
            },
            "System.Text.Encodings.Web": {"type": "Transitive", "resolved": "4.5.0"},
            "MyLib": {"type": "Project"},
        }
    },
}

PIPFILE_LOCK = {
    "default": {"requests": {"version": "==2.19.0"}, "urllib3": {"version": "==1.24.1"}},
    "develop": {"jinja2": {"version": "==2.10"}},
}
PIPFILE = '[packages]\nrequests = "*"\n\n[dev-packages]\njinja2 = "*"\n'


def _packages(name: str, text: str) -> set[tuple[str, str, str]]:
    parser = mp._parser_for(name)
    assert parser is not None
    return {(p.ecosystem, p.name, p.version) for p in parser(text)}


# ── Lockfile readers ──────────────────────────────────────────────────────────


def test_go_mod_requires_and_toolchain() -> None:
    assert _packages("go.mod", GO_MOD) == {
        ("Go", "stdlib", "1.22.1"),
        ("Go", "github.com/gin-gonic/gin", "v1.9.0"),
        ("Go", "golang.org/x/net", "v0.7.0"),
        ("Go", "github.com/pkg/errors", "v0.9.1"),
    }


def test_go_directive_alone_is_not_a_toolchain() -> None:
    assert _packages("go.mod", "module a\n\ngo 1.22\n") == set()


def test_pubspec_lock_hosted_only() -> None:
    assert _packages("pubspec.lock", PUBSPEC_LOCK) == {
        ("Pub", "http", "0.13.2"),
        ("Pub", "mocktail", "1.0.0"),
        ("Pub", "meta", "1.9.1"),
    }


def test_cargo_lock_registry_crates_only() -> None:
    assert _packages("Cargo.lock", CARGO_LOCK) == {
        ("crates.io", "chrono", "0.4.19"),
        ("crates.io", "time", "0.1.43"),
    }


def test_gemfile_lock_strips_platform() -> None:
    assert _packages("Gemfile.lock", GEMFILE_LOCK) == {
        ("RubyGems", "loofah", "2.19.0"),
        ("RubyGems", "nokogiri", "1.13.0"),
        ("RubyGems", "racc", "1.6.0"),
    }


def test_nuget_lock_skips_projects() -> None:
    assert _packages("packages.lock.json", json.dumps(NUGET_LOCK)) == {
        ("NuGet", "Newtonsoft.Json", "12.0.1"),
        ("NuGet", "Html.Abstractions", "2.1.0"),
        ("NuGet", "System.Text.Encodings.Web", "4.5.0"),
    }


def test_pipfile_lock() -> None:
    assert _packages("Pipfile.lock", json.dumps(PIPFILE_LOCK)) == {
        ("PyPI", "requests", "2.19.0"),
        ("PyPI", "urllib3", "1.24.1"),
        ("PyPI", "jinja2", "2.10"),
    }


# ── Install paths and dev-only ────────────────────────────────────────────────


def test_paths_through_the_graph(tmp_path: Path) -> None:
    (tmp_path / "Cargo.lock").write_text(CARGO_LOCK)
    (tmp_path / "Gemfile.lock").write_text(GEMFILE_LOCK)
    (tmp_path / "packages.lock.json").write_text(json.dumps(NUGET_LOCK))
    assert read_graph(tmp_path / "Cargo.lock").paths_to("time") == ["chrono › time"]
    assert read_graph(tmp_path / "Gemfile.lock").paths_to("nokogiri") == ["loofah › nokogiri"]
    nuget = read_graph(tmp_path / "packages.lock.json")
    assert nuget.paths_to("System.Text.Encodings.Web") == [
        "Html.Abstractions › System.Text.Encodings.Web"
    ]
    assert nuget.paths_to("Newtonsoft.Json") == ["Newtonsoft.Json"]


def test_npm_runtime_paths_first_and_dev_only(tmp_path: Path) -> None:
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"typeorm": "^1"}, "devDependencies": {"vitest": "^5"}},
            "node_modules/typeorm": {"version": "1.1.1", "dependencies": {"tinyglobby": "^0"}},
            "node_modules/tinyglobby": {"version": "0.2.1", "dependencies": {"picomatch": "^4"}},
            "node_modules/vitest": {
                "version": "5.0.1",
                "dev": True,
                "dependencies": {"picomatch": "^4"},
            },
            "node_modules/picomatch": {"version": "4.0.7"},
            "node_modules/chai": {"version": "5.0.0", "dev": True},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    graph = read_graph(tmp_path / "package-lock.json")
    assert graph.paths_to("picomatch") == [
        "typeorm › tinyglobby › picomatch",
        "vitest › picomatch",
    ]
    assert not graph.is_dev_only("picomatch")
    assert graph.is_dev_only("chai")
    assert graph.is_dev_only("vitest")


def test_pubspec_and_pipfile_dev(tmp_path: Path) -> None:
    (tmp_path / "pubspec.lock").write_text(PUBSPEC_LOCK)
    (tmp_path / "Pipfile.lock").write_text(json.dumps(PIPFILE_LOCK))
    (tmp_path / "Pipfile").write_text(PIPFILE)
    pub = read_graph(tmp_path / "pubspec.lock")
    assert pub.is_dev_only("mocktail") and not pub.is_dev_only("http")
    pipenv = read_graph(tmp_path / "Pipfile.lock")
    assert pipenv.is_dev_only("jinja2") and "requests" in pipenv.direct


# ── The check, with OSV mocked ────────────────────────────────────────────────


ADVISORIES = {
    "GHSA-time-0001": {
        "summary": "Segmentation fault in time",
        "aliases": ["CVE-2020-26235"],
        "database_specific": {"severity": "MODERATE"},
        "affected": [
            {
                "package": {"name": "time"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "0.2.23"}]}],
            }
        ],
    },
    "GHSA-noko-0001": {
        "summary": "nokogiri issue one",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {"package": {"name": "nokogiri"}, "ranges": [{"events": [{"fixed": "1.13.4"}]}]}
        ],
    },
    "GHSA-noko-0002": {
        "summary": "nokogiri issue two",
        "database_specific": {"severity": "CRITICAL"},
        "affected": [
            {"package": {"name": "nokogiri"}, "ranges": [{"events": [{"fixed": "1.16.5"}]}]}
        ],
    },
    "GO-2024-0001": {
        "summary": "net/http issue",
        "aliases": ["GHSA-gogo-0001"],
        "affected": [
            {"package": {"name": "stdlib"}, "ranges": [{"events": [{"fixed": "1.22.4"}]}]}
        ],
    },
    "GHSA-gogo-0001": {"database_specific": {"severity": "LOW"}},
    "GHSA-mock-0001": {
        "summary": "mocktail issue",
        "database_specific": {"severity": "HIGH"},
        "affected": [],
    },
}
IDS = {
    ("crates.io", "time"): ["GHSA-time-0001"],
    ("RubyGems", "nokogiri"): ["GHSA-noko-0001", "GHSA-noko-0002", "MAL-2024-1"],
    ("Go", "stdlib"): ["GO-2024-0001"],
    ("Pub", "mocktail"): ["GHSA-mock-0001"],
}


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "rust").mkdir()
    (tmp_path / "rust" / "Cargo.lock").write_text(CARGO_LOCK)
    (tmp_path / "ruby").mkdir()
    (tmp_path / "ruby" / "Gemfile.lock").write_text(GEMFILE_LOCK)
    (tmp_path / "go").mkdir()
    (tmp_path / "go" / "go.mod").write_text(GO_MOD)
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "pubspec.lock").write_text(PUBSPEC_LOCK)
    monkeypatch.setattr(osv_deps, "is_tool_available", lambda tool: False)
    monkeypatch.setattr(mp, "network_disabled", lambda: False)
    monkeypatch.setattr(
        mp,
        "query_vulnerability_ids",
        lambda packages: {
            p: IDS[(p.ecosystem, p.name)] for p in packages if (p.ecosystem, p.name) in IDS
        },
    )
    monkeypatch.setattr(
        osv_deps, "_fetch_all", lambda ids: {i: ADVISORIES[i] for i in ids if i in ADVISORIES}
    )
    return tmp_path


def test_one_finding_per_package_with_paths_and_fix(project: Path) -> None:
    result = asyncio.run(osv_deps.run_osv_dependency_check(str(project)))
    by_pkg = {f.package: f for f in result.findings}
    assert set(by_pkg) == {"time", "nokogiri", "stdlib", "mocktail"}

    noko = by_pkg["nokogiri"]
    assert noko.title == "nokogiri: 2 known vulnerabilities"
    assert noko.severity == Severity.CRITICAL  # the most severe advisory
    assert noko.rule_id == "GHSA-noko-0002"
    assert noko.dependency_paths == ["loofah › nokogiri"]
    # The highest of each advisory's nearest fix clears both.
    assert noko.fix_guidance.startswith("Upgrade nokogiri to 1.16.5: update loofah")
    assert "MAL-" not in noko.description  # reported by the known-malicious check

    time = by_pkg["time"]
    assert time.title == "time: Segmentation fault in time"
    assert time.version == "0.1.43" and time.file == "rust/Cargo.lock"
    assert "(via chrono)" in time.description
    assert "cargo update -p time --precise 0.2.23" in time.fix_guidance

    go = by_pkg["stdlib"]
    assert go.title == "Go toolchain: net/http issue"
    assert go.severity == Severity.LOW  # from the GHSA alias
    assert go.fix_guidance == "Build with Go 1.22.4 or later (set `toolchain go1.22.4` in go.mod)."

    mock = by_pkg["mocktail"]
    assert mock.context == "dev-dependency" and mock.severity == Severity.MEDIUM
    assert mock.fix_guidance.startswith("No patched version of mocktail is published yet")


def test_skipped_without_network(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mp, "network_disabled", lambda: True)
    result = asyncio.run(osv_deps.run_osv_dependency_check(str(project)))
    assert result.findings == []
    assert "network disabled" in result.metadata["skipped"]


def test_left_to_installed_tools() -> None:
    npm = Package("npm", "lodash", "4.17.15")
    pypi = Package("PyPI", "requests", "2.19.0")
    available = {"npm", "pip-audit", "govulncheck", "go"}
    original = osv_deps.is_tool_available
    try:
        osv_deps.is_tool_available = lambda tool: tool in available  # type: ignore[assignment]
        assert osv_deps.covered_elsewhere(npm, ["web/package-lock.json"]) == "npm audit"
        assert osv_deps.covered_elsewhere(npm, ["web/yarn.lock"]) == ""  # npm audit can't read it
        assert osv_deps.covered_elsewhere(pypi, ["requirements.txt"]) == "pip-audit"
        assert osv_deps.covered_elsewhere(pypi, ["poetry.lock"]) == ""  # pip-audit can't read it
        assert (
            osv_deps.covered_elsewhere(Package("Go", "x.io/y", "v1"), ["go.mod"]) == "govulncheck"
        )
        assert osv_deps.covered_elsewhere(Package("Pub", "http", "1"), ["pubspec.lock"]) == ""
    finally:
        osv_deps.is_tool_available = original  # type: ignore[assignment]


@pytest.mark.parametrize(
    ("ecosystem", "direct_hint"),
    [
        ("npm", "npm install lodash@2.0.0"),
        ("PyPI", "set lodash>=2.0.0 in your requirements"),
        ("Go", "go get lodash@v2.0.0"),
        ("Pub", "set lodash: ^2.0.0 in pubspec.yaml"),
        ("crates.io", 'set lodash = "2.0.0" in Cargo.toml'),
        ("RubyGems", "bundle update lodash"),
        ("NuGet", "update the PackageReference for lodash to 2.0.0"),
        ("Packagist", "composer require lodash:^2.0.0"),
    ],
)
def test_fix_advice_per_ecosystem(ecosystem: str, direct_hint: str) -> None:
    package = Package(ecosystem, "lodash", "1.0.0")
    assert direct_hint in osv_deps.fix_advice(package, "2.0.0", ["lodash"])
    assert "update app, which brings it in" in osv_deps.fix_advice(
        package, "2.0.0", ["app › lodash"]
    )
    assert osv_deps.fix_advice(package, "2.0.0", ["lodash"], unfixed=1).endswith(
        "1 advisory has no fix yet."
    )
