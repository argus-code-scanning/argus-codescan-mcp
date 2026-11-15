"""Typosquatted and non-existent dependencies (#142). Registry calls are mocked."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from argus.models import Severity
from argus.tools import typosquats as ts


@pytest.mark.parametrize(
    ("ecosystem", "name", "target", "how"),
    [
        ("pypi", "reqeusts", "requests", "one character"),
        ("pypi", "urlib3", "urllib3", "one character"),
        ("pypi", "djanga", "django", "one character"),
        ("pypi", "Pandsa", "pandas", "one character"),  # case-insensitive (PEP 503)
        ("npm", "loadsh", "lodash", "one character"),
        ("npm", "expresss", "express", "one character"),
        ("npm", "electorn", "electron", "one character"),
        ("npm", "discordi.js", "discord.js", "one character"),
        ("npm", "crossenv", "cross-env", "separators"),
        ("npm", "node-fetch-js", "node-fetch", "-js"),
    ],
)
def test_known_typosquat_patterns_are_caught(
    ecosystem: str, name: str, target: str, how: str
) -> None:
    hit = ts.lookalike(ecosystem, name)
    assert hit is not None and hit[0] == target and how in hit[1]


@pytest.mark.parametrize(
    ("ecosystem", "name"),
    [
        ("pypi", "requests"),
        ("pypi", "Django"),
        ("pypi", "python-dateutil"),
        ("pypi", "nvidia-cudnn-cu11"),  # digit-only difference from -cu12
        ("pypi", "bump2version"),
        ("npm", "react"),
        ("npm", "@babel/core"),
        ("npm", "@babel/cor"),  # scoped: only the scope owner can publish under @babel
        ("npm", "ramda"),
        ("npm", "qs"),  # short names are one edit from many others
        ("npm", "my-company-internal-utils"),
    ],
)
def test_popular_scoped_short_and_unrelated_names_are_quiet(ecosystem: str, name: str) -> None:
    assert ts.lookalike(ecosystem, name) is None


def _project(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def test_manifests_are_parsed_and_findings_point_at_the_line(tmp_path: Path) -> None:
    _project(
        tmp_path,
        {
            "package.json": json.dumps(
                {"dependencies": {"react": "^18", "loadsh": "^4"}}, indent=2
            ),
            "api/requirements.txt": "# deps\nflask==3.0.0\nreqeusts>=2\n-e ./local\n",
            "svc/pyproject.toml": '[project]\nname = "svc"\ndependencies = ["djanga>=4"]\n',
            "tests/fixtures/package.json": json.dumps({"dependencies": {"expresss": "1"}}),
        },
    )
    findings, meta = ts.typosquat_findings(str(tmp_path))
    got = {(f.file, f.line, f.title.split("'")[1]) for f in findings}
    assert got == {
        ("package.json", 4, "loadsh"),
        ("api/requirements.txt", 3, "reqeusts"),
        ("svc/pyproject.toml", 3, "djanga"),
    }
    assert all(
        f.severity == Severity.MEDIUM and f.rule_id == "typosquat-lookalike" for f in findings
    )
    assert meta["dependencies_checked"] == 5  # fixtures are skipped


def test_registry_check_is_off_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ARGUS_NO_NETWORK", raising=False)

    def must_not_call(ecosystem: str, name: str) -> tuple[bool, None]:
        raise AssertionError("registry lookups are opt-in")

    monkeypatch.setattr(ts, "registry_status", must_not_call)
    _project(tmp_path, {"requirements.txt": "some-unknown-lib==1.0\n"})
    findings, _ = ts.typosquat_findings(str(tmp_path))
    assert findings == []


def test_registry_check_flags_missing_and_new_packages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ARGUS_NO_NETWORK", raising=False)
    monkeypatch.setenv("ARGUS_REGISTRY_CHECK", "1")
    now = datetime.now(timezone.utc)
    answers = {
        "fastapi-auth-helperz": (False, None),  # made-up name
        "brand-new-lib": (True, now - timedelta(days=3)),
        "old-niche-lib": (True, now - timedelta(days=900)),
    }
    looked_up: list[str] = []

    def fake_status(ecosystem: str, name: str) -> tuple[bool, datetime | None]:
        looked_up.append(name)
        return answers[name]

    monkeypatch.setattr(ts, "registry_status", fake_status)
    _project(
        tmp_path,
        {
            "requirements.txt": "requests==2.32.0\nfastapi-auth-helperz==0.1\nbrand-new-lib==1.0\nold-niche-lib==2.0\n"
        },
    )
    findings, meta = ts.typosquat_findings(str(tmp_path))
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["dependency-not-on-registry"].severity == Severity.HIGH
    assert "fastapi-auth-helperz" in by_rule["dependency-not-on-registry"].title
    assert by_rule["dependency-recently-published"].severity == Severity.MEDIUM
    assert "requests" not in looked_up  # popular packages are not looked up


def test_private_registry_skips_existence_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ARGUS_NO_NETWORK", raising=False)
    monkeypatch.setenv("ARGUS_REGISTRY_CHECK", "1")
    monkeypatch.setattr(
        ts, "registry_status", lambda e, n: (_ for _ in ()).throw(AssertionError("no lookups"))
    )
    _project(
        tmp_path,
        {
            "requirements.txt": "--extra-index-url https://pypi.internal.example/simple\ncompany-lib==1.0\n",
            ".npmrc": "registry=https://npm.internal.example/\n",
            "package.json": json.dumps({"dependencies": {"@corp/ui": "1"}}),
        },
    )
    findings, meta = ts.typosquat_findings(str(tmp_path))
    assert findings == []
    assert meta["registry_check"]["private_registry_skipped"] == ["npm", "pypi"]


def test_no_network_skips_the_registry_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ARGUS_REGISTRY_CHECK", "1")  # ARGUS_NO_NETWORK=1 from conftest
    _project(tmp_path, {"requirements.txt": "unknown-lib==1\n"})
    _, meta = ts.typosquat_findings(str(tmp_path))
    assert meta["registry_check"] == "skipped: network disabled"


@pytest.mark.asyncio
async def test_part_of_the_sca_scan(tmp_path: Path) -> None:
    from argus.tools.sca import run_all_sca

    _project(tmp_path, {"requirements.txt": "reqeusts==2.0\n"})
    results = await run_all_sca(str(tmp_path))
    typo = next(r for r in results if r.tool == "argus-typosquats")
    assert [f.rule_id for f in typo.findings] == ["typosquat-lookalike"]
