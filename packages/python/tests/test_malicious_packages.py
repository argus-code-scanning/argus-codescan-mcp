"""Known-malicious packages via OSV MAL- records (#141). OSV is mocked: no network in tests."""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path
from typing import Any

import pytest

from argus.models import Severity
from argus.tools import malicious_packages as mp

PACKAGE_LOCK_V3 = {
    "name": "app",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "dependencies": {"evil-pkg": "1.0.0"}},
        "node_modules/evil-pkg": {"version": "1.0.0"},
        "node_modules/@scope/good": {"version": "2.1.0"},
        "node_modules/a/node_modules/evil-pkg": {"version": "1.0.0"},
        "node_modules/local": {"link": True},
    },
}

PACKAGE_LOCK_V1 = {
    "lockfileVersion": 1,
    "dependencies": {
        "outer": {"version": "1.0.0", "dependencies": {"inner": {"version": "0.2.0"}}},
        "linked": {"version": "file:../linked"},
    },
}

YARN_CLASSIC = """# yarn lockfile v1

"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.24.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.24.0.tgz"

lodash@^4.17.0:
  version "4.17.21"
"""

YARN_BERRY = """__metadata:
  version: 8

"left-pad@npm:^1.3.0":
  version: 1.3.0
  resolution: "left-pad@npm:1.3.0"

"app@workspace:.":
  version: 0.0.0-use.local
"""

PNPM_V9 = """lockfileVersion: '9.0'
packages:
  '@types/node@20.11.0':
    resolution: {integrity: sha512-x}
  lodash@4.17.21:
    resolution: {integrity: sha512-y}
  react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-z}
"""

PNPM_V5 = """lockfileVersion: 5.4
packages:
  /lodash/4.17.21:
    resolution: {integrity: sha512-y}
"""

POETRY_LOCK = """[[package]]
name = "Requests"
version = "2.31.0"

[[package]]
name = "my_lib"
version = "0.1.0"
"""

UV_LOCK = """version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "httpx"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }
"""

REQUIREMENTS = """# pinned
flask==3.0.0
Django[argon2]==5.0.1 ; python_version >= "3.10"
requests>=2.0
-e ./local
urllib3===2.2.1 --hash=sha256:abc
"""

COMPOSER_LOCK = {
    "packages": [{"name": "monolog/monolog", "version": "v3.5.0"}],
    "packages-dev": [{"name": "phpunit/phpunit", "version": "10.5.0"}],
}


def _parse(parser, text: str) -> set[tuple[str, str, str]]:
    return {(p.ecosystem, p.name, p.version) for p in parser(text)}


def test_package_lock_v3_and_v1() -> None:
    assert _parse(mp._npm_package_lock, json.dumps(PACKAGE_LOCK_V3)) == {
        ("npm", "evil-pkg", "1.0.0"),
        ("npm", "@scope/good", "2.1.0"),
    }
    assert _parse(mp._npm_package_lock, json.dumps(PACKAGE_LOCK_V1)) == {
        ("npm", "outer", "1.0.0"),
        ("npm", "inner", "0.2.0"),
    }


def test_yarn_classic_and_berry() -> None:
    assert _parse(mp._yarn_lock, YARN_CLASSIC) == {
        ("npm", "@babel/core", "7.24.0"),
        ("npm", "lodash", "4.17.21"),
    }
    assert _parse(mp._yarn_lock, YARN_BERRY) == {("npm", "left-pad", "1.3.0")}


def test_pnpm_v9_and_v5() -> None:
    assert _parse(mp._pnpm_lock, PNPM_V9) == {
        ("npm", "@types/node", "20.11.0"),
        ("npm", "lodash", "4.17.21"),
        ("npm", "react-dom", "18.2.0"),
    }
    assert _parse(mp._pnpm_lock, PNPM_V5) == {("npm", "lodash", "4.17.21")}


@pytest.mark.skipif(mp._toml is None, reason="no TOML parser on this Python")
def test_poetry_and_uv_locks() -> None:
    assert _parse(mp._toml_packages, POETRY_LOCK) == {
        ("PyPI", "Requests", "2.31.0"),
        ("PyPI", "my_lib", "0.1.0"),
    }
    # The editable project itself is skipped.
    assert _parse(mp._toml_packages, UV_LOCK) == {("PyPI", "httpx", "0.27.0")}


def test_requirements_only_exact_pins() -> None:
    assert _parse(mp._requirements, REQUIREMENTS) == {
        ("PyPI", "flask", "3.0.0"),
        ("PyPI", "Django", "5.0.1"),
        ("PyPI", "urllib3", "2.2.1"),
    }


def test_composer_lock_strips_v_prefix() -> None:
    assert _parse(mp._composer_lock, json.dumps(COMPOSER_LOCK)) == {
        ("Packagist", "monolog/monolog", "3.5.0"),
        ("Packagist", "phpunit/phpunit", "10.5.0"),
    }


def test_find_lockfiles_skips_node_modules_and_venv(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "requirements-dev.txt").write_text("")
    for skipped in ("node_modules/x", ".venv/lib"):
        (tmp_path / skipped).mkdir(parents=True)
        (tmp_path / skipped / "package-lock.json").write_text("{}")
    found = {p.relative_to(tmp_path).as_posix() for p in mp.find_lockfiles(tmp_path)}
    assert found == {"package-lock.json", "api/requirements-dev.txt"}


class FakeOSV:
    """Stands in for api.osv.dev/v1/querybatch."""

    def __init__(self, malicious: dict[tuple[str, str, str], list[str]]) -> None:
        self.malicious = malicious
        self.queries: list[dict[str, Any]] = []

    def __call__(self, queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        self.queries.extend(queries)
        out = []
        for q in queries:
            key = (q["package"]["ecosystem"], q["package"]["name"], q["version"])
            ids = self.malicious.get(key, [])
            out.append({"vulns": [{"id": i} for i in ids]} if ids else {})
        return out


@pytest.mark.asyncio
async def test_malicious_package_is_a_critical_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ARGUS_NO_NETWORK", raising=False)
    (tmp_path / "package-lock.json").write_text(json.dumps(PACKAGE_LOCK_V3, indent=2))
    fake = FakeOSV({("npm", "evil-pkg", "1.0.0"): ["MAL-2026-593", "GHSA-xxxx-yyyy-zzzz"]})
    monkeypatch.setattr(mp, "_post_querybatch", fake)

    result = await mp.run_malicious_package_check(str(tmp_path))

    assert result.errors == []
    assert result.metadata["packages_checked"] == 2  # duplicates and links collapse
    assert len(result.findings) == 1  # one finding per lockfile location
    finding = result.findings[0]
    assert finding.severity == Severity.CRITICAL
    assert finding.title == "Known malicious package: evil-pkg@1.0.0"
    assert finding.rule_id == "MAL-2026-593"
    assert finding.file == "package-lock.json"
    assert finding.line > 1
    assert finding.references == ["https://osv.dev/vulnerability/MAL-2026-593"]
    assert finding.to_dict()["confidence"] == "high"


@pytest.mark.asyncio
async def test_vulnerabilities_that_are_not_malware_are_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ARGUS_NO_NETWORK", raising=False)
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")
    monkeypatch.setattr(mp, "_post_querybatch", FakeOSV({("PyPI", "flask", "3.0.0"): []}))
    result = await mp.run_malicious_package_check(str(tmp_path))
    assert result.findings == []


@pytest.mark.asyncio
async def test_pypi_names_are_normalised_for_osv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ARGUS_NO_NETWORK", raising=False)
    (tmp_path / "requirements.txt").write_text("My_Evil.Lib==0.0.1\n")
    fake = FakeOSV({("PyPI", "my-evil-lib", "0.0.1"): ["MAL-2026-1"]})
    monkeypatch.setattr(mp, "_post_querybatch", fake)
    result = await mp.run_malicious_package_check(str(tmp_path))
    assert fake.queries[0]["package"]["name"] == "my-evil-lib"
    assert [f.rule_id for f in result.findings] == ["MAL-2026-1"]


@pytest.mark.asyncio
async def test_offline_is_a_note_not_a_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ARGUS_NO_NETWORK", raising=False)
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")

    def offline(_queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(mp, "_post_querybatch", offline)
    result = await mp.run_malicious_package_check(str(tmp_path))
    assert result.findings == []
    assert "network unavailable" in result.errors[0]


@pytest.mark.asyncio
async def test_no_network_switch_skips_the_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ARGUS_NO_NETWORK", "1")
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")

    def must_not_call(_queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        raise AssertionError("OSV must not be called when the network is disabled")

    monkeypatch.setattr(mp, "_post_querybatch", must_not_call)
    result = await mp.run_malicious_package_check(str(tmp_path))
    assert result.findings == []
    assert "network disabled" in result.metadata["skipped"]


@pytest.mark.asyncio
async def test_no_lockfiles_means_no_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ARGUS_NO_NETWORK", raising=False)
    (tmp_path / "app.py").write_text("print('hi')\n")

    def must_not_call(_queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        raise AssertionError("no packages, no request")

    monkeypatch.setattr(mp, "_post_querybatch", must_not_call)
    result = await mp.run_malicious_package_check(str(tmp_path))
    assert result.findings == [] and result.metadata["packages_checked"] == 0


@pytest.mark.asyncio
async def test_malformed_lockfile_is_reported_and_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ARGUS_NO_NETWORK", "1")
    (tmp_path / "package-lock.json").write_text("{not json")
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")
    result = await mp.run_malicious_package_check(str(tmp_path))
    assert result.metadata["lockfiles"] == ["requirements.txt"]
    assert any("package-lock.json" in e for e in result.errors)


def test_batches_are_split_at_the_osv_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    sizes: list[int] = []

    def fake(queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        sizes.append(len(queries))
        return [{} for _ in queries]

    monkeypatch.setattr(mp, "_post_querybatch", fake)
    packages = [mp.Package("npm", f"p{i}", "1.0.0") for i in range(2500)]
    assert mp.lookup_malicious(packages) == {}
    assert sizes == [1000, 1000, 500]
