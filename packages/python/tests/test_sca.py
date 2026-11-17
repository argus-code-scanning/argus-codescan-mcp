"""Tests for SCA runners (pip-audit, npm audit, govulncheck, composer audit)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from argus.models import Severity
from argus.tools import sca


@pytest.fixture(autouse=True)
def _tools_available(monkeypatch):
    monkeypatch.setattr(sca, "is_tool_available", lambda name: True)
    # Never hit the network from tests.
    monkeypatch.setattr(sca, "_osv_severity", lambda vuln_id: None)


def _fake_runner(monkeypatch, handler):
    calls: list[tuple[list[str], str | None]] = []

    async def fake_run_command(cmd, cwd=None, timeout=300, env=None):
        calls.append((cmd, cwd))
        return handler(cmd, cwd)

    monkeypatch.setattr(sca, "run_command", fake_run_command)
    return calls


# ── npm audit ────────────────────────────────────────────────────────────────

NPM_FULL = {
    "vulnerabilities": {
        "js-yaml": {
            "severity": "high",
            "via": [
                {
                    "source": 1,
                    "title": "JS-YAML: Quadratic CPU consumption",
                    "url": "https://github.com/advisories/GHSA-5p4m-2wfm-xmqj",
                    "severity": "high",
                    "cwe": ["CWE-407"],
                    "range": "4.0.0 - 4.3.1",
                },
            ],
            "fixAvailable": True,
        },
        "brace-expansion": {
            "severity": "high",
            "via": [
                {
                    "source": 2,
                    "title": "brace-expansion: DoS via unbounded expansion length",
                    "url": "https://github.com/advisories/GHSA-mh99-v99m-4gvg",
                    "severity": "high",
                    "range": "<=1.1.20",
                },
                {
                    "source": 3,
                    "title": "brace-expansion: Quadratic-time expansion",
                    "url": "https://github.com/advisories/GHSA-q2hr-2g5m-vwhr",
                    "severity": "moderate",
                    "range": "<=1.1.20",
                },
            ],
            "fixAvailable": True,
        },
        "vitest": {
            "severity": "critical",
            "via": [
                {
                    "source": 4,
                    "title": "When Vitest UI server is listening, arbitrary file can be read",
                    "url": "https://github.com/advisories/GHSA-5xrq-8626-4rwp",
                    "severity": "critical",
                    "range": "<=4.1.10",
                },
                "vite",
            ],
            "fixAvailable": {"name": "vitest", "version": "5.0.5", "isSemVerMajor": True},
        },
        # Only points at another package's advisory: no finding of its own.
        "vite-node": {"severity": "moderate", "via": ["vite"], "fixAvailable": True},
    }
}
NPM_PROD = {
    "vulnerabilities": {k: NPM_FULL["vulnerabilities"][k] for k in ("js-yaml", "brace-expansion")}
}


def _npm_tree(tmp_path: Path) -> None:
    for project in ("packages/npm", "extensions/vscode"):
        (tmp_path / project).mkdir(parents=True)
        (tmp_path / project / "package.json").write_text("{}")
        (tmp_path / project / "package-lock.json").write_text("{}")
    # Workspace member covered by the packages/npm lockfile.
    (tmp_path / "packages/npm/workspace").mkdir()
    (tmp_path / "packages/npm/workspace/package.json").write_text("{}")
    # Standalone package without a lockfile.
    (tmp_path / "web").mkdir()
    (tmp_path / "web/package.json").write_text("{}")


def test_npm_audit_scans_every_locked_project(tmp_path, monkeypatch):
    _npm_tree(tmp_path)

    def handler(cmd, cwd):
        if cwd.endswith("extensions/vscode"):
            return 0, json.dumps({"vulnerabilities": {}}), ""
        return 1, json.dumps(NPM_PROD if "--omit=dev" in cmd else NPM_FULL), ""

    calls = _fake_runner(monkeypatch, handler)
    result = asyncio.run(sca.run_npm_audit(str(tmp_path)))

    audited = sorted({Path(cwd).relative_to(tmp_path).as_posix() for _, cwd in calls})
    assert audited == ["extensions/vscode", "packages/npm"]
    assert len(result.errors) == 1
    assert str(tmp_path / "web") in result.errors[0]
    assert "workspace" not in result.errors[0]


def test_npm_audit_one_finding_per_advisory_with_scope(tmp_path, monkeypatch):
    _npm_tree(tmp_path)
    _fake_runner(
        monkeypatch,
        lambda cmd, cwd: (1, json.dumps(NPM_PROD if "--omit=dev" in cmd else NPM_FULL), ""),
    )

    result = asyncio.run(sca.run_npm_audit(str(tmp_path / "packages/npm")))
    by_id = {f.cve: f for f in result.findings}

    assert set(by_id) == {
        "GHSA-5p4m-2wfm-xmqj",
        "GHSA-mh99-v99m-4gvg",
        "GHSA-q2hr-2g5m-vwhr",
        "GHSA-5xrq-8626-4rwp",
    }
    assert by_id["GHSA-5p4m-2wfm-xmqj"].description.startswith("[runtime dependency]")
    assert by_id["GHSA-5xrq-8626-4rwp"].description.startswith("[dev dependency]")
    # Dev-only: the critical advisory is lowered one level and tagged, like findings in tests.
    assert by_id["GHSA-5xrq-8626-4rwp"].severity == Severity.HIGH
    assert by_id["GHSA-5xrq-8626-4rwp"].context == "dev-dependency"
    assert by_id["GHSA-5p4m-2wfm-xmqj"].context == ""
    assert by_id["GHSA-q2hr-2g5m-vwhr"].severity == Severity.MEDIUM
    assert by_id["GHSA-5p4m-2wfm-xmqj"].cwe == "CWE-407"
    assert by_id["GHSA-mh99-v99m-4gvg"].title == (
        "brace-expansion: DoS via unbounded expansion length"
    )
    assert by_id["GHSA-5xrq-8626-4rwp"].fix_guidance == (
        "Upgrade vitest to 5.0.5 (major version upgrade)"
    )
    assert by_id["GHSA-5p4m-2wfm-xmqj"].file.endswith("package-lock.json")


# ── pip-audit ────────────────────────────────────────────────────────────────

PIP_AUDIT_OUTPUT = {
    "dependencies": [
        {"name": "requests", "version": "2.0.0", "vulns": []},
        {
            "name": "pyjwt",
            "version": "2.13.0",
            "vulns": [
                {
                    "id": "PYSEC-2026-4145",
                    "fix_versions": ["2.14.0"],
                    "aliases": ["CVE-2026-1234", "GHSA-aaaa-bbbb-cccc"],
                    "description": "Signature bypass",
                }
            ],
        },
    ],
    "fixes": [],
}


def test_pip_audit_audits_project_manifests_not_own_environment(tmp_path, monkeypatch):
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc/pyproject.toml").write_text("[project]\nname='svc'\n")
    (tmp_path / "requirements.txt").write_text("pyjwt==2.13.0\n")
    (tmp_path / "requirements-dev.txt").write_text("pytest\n")
    calls = _fake_runner(monkeypatch, lambda cmd, cwd: (1, json.dumps(PIP_AUDIT_OUTPUT), ""))
    looked_up: list[str] = []

    def fake_osv(vuln_id):
        looked_up.append(vuln_id)
        return Severity.CRITICAL if vuln_id.startswith("GHSA-") else None

    monkeypatch.setattr(sca, "_osv_severity", fake_osv)

    result = asyncio.run(sca.run_pip_audit(str(tmp_path)))

    targets = sorted(cmd[-1] for cmd, _ in calls)
    assert targets == sorted(
        [
            str(tmp_path / "requirements-dev.txt"),
            str(tmp_path / "requirements.txt"),
            str(tmp_path / "svc"),
        ]
    )
    assert len(result.findings) == 3
    finding = result.findings[0]
    assert finding.title == "pyjwt@2.13.0: PYSEC-2026-4145"
    assert finding.cve == "CVE-2026-1234"
    assert finding.severity == Severity.CRITICAL
    assert looked_up[0] == "GHSA-aaaa-bbbb-cccc"
    assert finding.fix_guidance == "Upgrade pyjwt to 2.14.0"


def test_pip_audit_without_python_manifests_runs_nothing(tmp_path, monkeypatch):
    (tmp_path / "index.js").write_text("")
    calls = _fake_runner(monkeypatch, lambda cmd, cwd: (0, "{}", ""))

    result = asyncio.run(sca.run_pip_audit(str(tmp_path)))

    assert calls == []
    assert result.findings == []


def test_pip_audit_severity_defaults_to_high_offline(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("pyjwt==2.13.0\n")
    _fake_runner(monkeypatch, lambda cmd, cwd: (1, json.dumps(PIP_AUDIT_OUTPUT), ""))

    result = asyncio.run(sca.run_pip_audit(str(tmp_path)))

    assert [f.severity for f in result.findings] == [Severity.HIGH]


# ── govulncheck ──────────────────────────────────────────────────────────────


def _govulncheck_stream() -> str:
    messages = [
        {"config": {"scan_level": "symbol"}},
        {
            "osv": {
                "id": "GO-2021-0113",
                "summary": "Out-of-bounds read in golang.org/x/text/language",
                "aliases": ["CVE-2021-38561", "GHSA-ppp9-7jff-5vj2"],
            }
        },
        {
            "osv": {
                "id": "GO-2020-0036",
                "summary": "Excessive resource consumption in YAML parsing",
                "aliases": ["CVE-2019-11254"],
            }
        },
        {"finding": {"osv": "GO-2021-0113", "trace": [{"module": "golang.org/x/text"}]}},
        {
            "finding": {
                "osv": "GO-2021-0113",
                "fixed_version": "v0.3.7",
                "trace": [
                    {
                        "module": "golang.org/x/text",
                        "version": "v0.3.5",
                        "package": "golang.org/x/text/language",
                        "function": "Parse",
                    },
                    {
                        "module": "example.com/app",
                        "package": "example.com/app",
                        "function": "main",
                        "position": {"filename": "main.go", "line": 11},
                    },
                ],
            }
        },
        {
            "finding": {
                "osv": "GO-2020-0036",
                "fixed_version": "v2.2.8",
                "trace": [
                    {
                        "module": "gopkg.in/yaml.v2",
                        "version": "v2.2.7",
                        "package": "gopkg.in/yaml.v2",
                    }
                ],
            }
        },
    ]
    # govulncheck pretty-prints each object.
    return "\n".join(json.dumps(m, indent=2) for m in messages)


def test_govulncheck_separates_called_from_not_called(tmp_path, monkeypatch):
    (tmp_path / "go.mod").write_text("module example.com/app\n")
    _fake_runner(monkeypatch, lambda cmd, cwd: (3, _govulncheck_stream(), ""))

    result = asyncio.run(sca.run_govulncheck(str(tmp_path)))
    by_id = {f.rule_id: f for f in result.findings}

    called = by_id["GO-2021-0113"]
    assert called.severity == Severity.HIGH
    assert called.description.startswith("[called] golang.org/x/text/language.Parse@v0.3.5")
    assert (called.file, called.line) == ("main.go", 11)
    assert called.cve == "CVE-2021-38561"
    assert called.fix_guidance == "Upgrade golang.org/x/text to v0.3.7"

    not_called = by_id["GO-2020-0036"]
    assert not_called.severity == Severity.LOW
    assert not_called.description.startswith("[not called]")
    assert not_called.file == str(tmp_path / "go.mod")


# ── composer audit ───────────────────────────────────────────────────────────


def _composer(advisories):
    return json.dumps({"advisories": advisories, "abandoned": []})


GUZZLE = {
    "advisoryId": "PKSA-gcrk-3vtt-1r14",
    "packageName": "guzzlehttp/guzzle",
    "affectedVersions": "<7.15.2",
    "title": "Guzzle: Noncanonical host can bypass host-based checks",
    "cve": "CVE-2026-69246",
    "link": "https://github.com/advisories/GHSA-v5mv-p594-2x33",
    "severity": "high",
}
TWIG = {
    "advisoryId": "PKSA-8zx5-v2nz-58pb",
    "packageName": "twig/twig",
    "affectedVersions": "<3.4.3",
    "title": "Twig: sandbox bypass",
    "cve": None,
    "link": "",
    "severity": None,
}


def test_composer_audit_scope_and_severity(tmp_path, monkeypatch):
    (tmp_path / "composer.lock").write_text("{}")

    def handler(cmd, cwd):
        if "--no-dev" in cmd:
            return 1, _composer({"guzzlehttp/guzzle": [GUZZLE]}), ""
        return 1, _composer({"guzzlehttp/guzzle": [GUZZLE], "twig/twig": [TWIG]}), ""

    _fake_runner(monkeypatch, handler)
    result = asyncio.run(sca.run_composer_audit(str(tmp_path)))
    by_pkg = {f.title.split(":")[0]: f for f in result.findings}

    assert by_pkg["guzzlehttp/guzzle"].description.startswith("[runtime dependency]")
    assert by_pkg["guzzlehttp/guzzle"].severity == Severity.HIGH
    assert by_pkg["guzzlehttp/guzzle"].cve == "CVE-2026-69246"
    assert by_pkg["twig/twig"].description.startswith("[dev dependency]")
    assert by_pkg["twig/twig"].cve == "PKSA-8zx5-v2nz-58pb"
    # twig is dev-only, so its high advisory is reported one level lower.
    assert by_pkg["twig/twig"].severity == Severity.MEDIUM
    assert by_pkg["twig/twig"].context == "dev-dependency"


def test_composer_audit_clean_project(tmp_path, monkeypatch):
    (tmp_path / "composer.lock").write_text("{}")
    _fake_runner(monkeypatch, lambda cmd, cwd: (0, _composer([]), ""))

    result = asyncio.run(sca.run_composer_audit(str(tmp_path)))

    assert result.findings == []
    assert result.errors == []


# ── run_all_sca ──────────────────────────────────────────────────────────────


def test_run_all_sca_adds_go_and_php_only_when_manifests_exist(tmp_path, monkeypatch):
    _fake_runner(monkeypatch, lambda cmd, cwd: (0, "{}", ""))

    tools = {r.tool for r in asyncio.run(sca.run_all_sca(str(tmp_path)))}
    assert "govulncheck" not in tools
    assert "composer-audit" not in tools

    (tmp_path / "go.mod").write_text("module x\n")
    (tmp_path / "composer.lock").write_text("{}")
    tools = {r.tool for r in asyncio.run(sca.run_all_sca(str(tmp_path)))}
    assert {"govulncheck", "composer-audit"} <= tools


def test_constant_key_property_injection_is_low_confidence():
    from argus.tools.sast import has_only_constant_keys

    rule = "javascript.express.security.audit.remote-property-injection.remote-property-injection"
    assert has_only_constant_keys(rule, "    request.headers[REQUEST_ID_HEADER] = id;")
    assert has_only_constant_keys(rule, "    res.locals['user'] = user;")
    assert not has_only_constant_keys(rule, "    target[req.body.key] = req.body.value;")
    assert not has_only_constant_keys(rule, "    store[name] = value;")
    assert not has_only_constant_keys("other-rule", "    headers[X] = 1;")
