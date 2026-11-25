"""PII redaction in reports, JSON, SARIF and MCP (#53) and data_policy (#54)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus import cli
from argus.models import AggregatedReport, Finding, ScanResult, ScanType, Severity
from argus.policy import DataPolicy, load_policy
from argus.redaction import redact_report, redact_text

PII = "Customer maria.gonzalez@gmail.com, SSN 219-09-9999, NI JG 10 32 87 B, card 4539 1488 0343 6467, phone +44 7700 912345"


def report(description: str = PII) -> dict:
    finding = Finding(
        title="Hardcoded personal data",
        severity=Severity.HIGH,
        scan_type=ScanType.SAST,
        tool="argus-pii",
        file="src/users.py",
        line=12,
        rule_id="pii-hardcoded-email",
        description=description,
        fix_guidance="Remove maria.gonzalez@gmail.com from the code.",
    )
    result = ScanResult(tool="argus-pii", scan_type=ScanType.SAST, target=".")
    result.findings.append(finding)
    return AggregatedReport(target=".", results=[result]).to_dict()


def test_redact_text_masks_every_kind() -> None:
    text, count = redact_text(PII)
    assert count == 5
    for kind in ("EMAIL", "SSN", "NINO", "CARD", "PHONE"):
        assert f"[REDACTED:{kind}]" in text
    assert "gmail" not in text and "9999" not in text and "6467" not in text


@pytest.mark.parametrize(
    "text",
    [
        "src/app.py:1234 line 56",
        "released 2026-11-25 as version 1.25.1",
        "listening on 192.168.10.200:8080",
        "card 4111 1111 1111 1112 fails Luhn",
        "order id 123456789012",
        "upgrade lodash from 4.17.20 to 4.17.21",
    ],
)
def test_redact_text_leaves_non_personal_data(text: str) -> None:
    assert redact_text(text) == (text, 0)


def test_keyed_tags_are_stable_and_need_a_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_REDACTION_KEY", "s3cret")
    a, _ = redact_report(report())
    b, _ = redact_report(report())
    desc = a["results"][0]["findings"][0]["description"]
    assert "[REDACTED:EMAIL:" in desc and desc == b["results"][0]["findings"][0]["description"]
    monkeypatch.setenv("ARGUS_REDACTION_KEY", "other")
    c, _ = redact_report(report())
    assert c["results"][0]["findings"][0]["description"] != desc
    monkeypatch.delenv("ARGUS_REDACTION_KEY")
    d, _ = redact_report(report())
    assert "[REDACTED:EMAIL]" in d["results"][0]["findings"][0]["description"]


def test_report_keeps_locations_and_drops_excluded_fields() -> None:
    out, count = redact_report(report(), exclude_fields=["fix_guidance", "file"])
    f = out["results"][0]["findings"][0]
    assert (f["file"], f["line"], f["rule_id"], f["severity"]) == (
        "src/users.py",
        12,
        "pii-hardcoded-email",
        "high",
    )
    assert "fix_guidance" not in f  # excluded; `file` can't be excluded
    assert count == 5 and out["redactions"] == 5


def test_max_snippet_lines() -> None:
    long = "\n".join(f"line {i}" for i in range(10))
    out, _ = redact_report(report(long), pii=False, max_snippet_lines=3)
    desc = out["results"][0]["findings"][0]["description"]
    assert desc.splitlines()[:3] == ["line 0", "line 1", "line 2"] and "7 more line(s)" in desc


def test_data_policy_from_argus_yml(tmp_path: Path) -> None:
    (tmp_path / ".argus.yml").write_text(
        "data_policy:\n  redact_pii: true\n  max_snippet_lines: 5\n  exclude_fields: [fix_guidance]\n"
    )
    dp = load_policy(start=str(tmp_path)).data_policy
    assert (dp.redact_pii, dp.max_snippet_lines, dp.exclude_fields) == ("true", 5, ["fix_guidance"])
    assert DataPolicy().should_redact(leaves_machine=True) is True
    assert DataPolicy().should_redact(leaves_machine=False) is False
    assert DataPolicy(redact_pii="false").should_redact(leaves_machine=True) is False
    assert DataPolicy(redact_pii="false").should_redact(leaves_machine=True, cli_flag=True) is True


@pytest.mark.parametrize(
    ("fmt", "flag", "policy", "masked"),
    [
        ("sarif", None, None, True),  # leaves the machine: masked by default
        ("json", None, None, False),  # local: kept for debugging
        ("json", True, None, True),  # --redact-pii
        ("sarif", False, None, False),  # --no-redact-pii
        ("json", None, DataPolicy(redact_pii="true"), True),
        ("sarif", None, DataPolicy(redact_pii="false"), False),
    ],
)
def test_cli_output_defaults(capsys, fmt, flag, policy, masked) -> None:
    code = cli._emit(report(), fmt, None, "low", "high", data_policy=policy, redact_flag=flag)
    out = capsys.readouterr().out
    assert ("gmail.com" not in out) is masked
    assert code == 1  # fail-on still sees the finding


def test_cli_flags_parse() -> None:
    parser = cli.build_parser()
    assert parser.parse_args(["scan", "code", ".", "--redact-pii"]).redact_pii is True
    assert parser.parse_args(["scan", "code", ".", "--no-redact-pii"]).redact_pii is False
    assert parser.parse_args(["scan", "code", "."]).redact_pii is None
    with pytest.raises(SystemExit):
        parser.parse_args(["scan", "code", ".", "--redact-pii", "--no-redact-pii"])


@pytest.mark.asyncio
async def test_mcp_responses_are_masked_unless_policy_says_not(tmp_path: Path) -> None:
    from argus.cloud_upload import ScanTimer
    from argus.server import _finish_scan

    def aggregated() -> AggregatedReport:
        r = ScanResult(tool="argus-pii", scan_type=ScanType.SAST, target=str(tmp_path))
        r.findings.append(
            Finding(
                title="x",
                severity=Severity.HIGH,
                scan_type=ScanType.SAST,
                tool="argus-pii",
                file="a.py",
                line=1,
                description=PII,
            )
        )
        return AggregatedReport(target=str(tmp_path), results=[r])

    out = await _finish_scan(
        aggregated(), scan_type="pii", timer=ScanTimer(), fmt="json", target_path=str(tmp_path)
    )
    assert "gmail.com" not in out[0].text and "[REDACTED:EMAIL]" in out[0].text
    assert json.loads(out[0].text)["results"][0]["findings"][0]["file"] == "a.py"
    (tmp_path / ".argus.yml").write_text("data_policy:\n  redact_pii: false\n")
    out = await _finish_scan(
        aggregated(), scan_type="pii", timer=ScanTimer(), fmt="json", target_path=str(tmp_path)
    )
    assert "gmail.com" in out[0].text
