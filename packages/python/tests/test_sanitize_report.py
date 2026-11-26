"""sanitize_report: a report that's safe to paste into an AI chat or a ticket (#59)."""

from __future__ import annotations

import json

import pytest

from argus.models import AggregatedReport, Finding, ScanResult, ScanType, Severity
from argus.redaction import mask_secret_values, sanitize_report


def report() -> dict:
    result = ScanResult(
        tool="argus-languages", scan_type=ScanType.SAST, target="/home/dev/acme/payments"
    )
    for sev, file, desc in [
        (Severity.LOW, "src/payments/util.py", "log line for maria.gonzalez@gmail.com"),
        (
            Severity.CRITICAL,
            "src/payments/keys.py",
            'aws = "AKIAIOSFODNN7EXAMPLE"; api_key = "sk_live_51HxAbCdEfGhIjKlMn"',
        ),
        (Severity.HIGH, "src/payments/db.py", "SQL built from request input"),
        (
            Severity.MEDIUM,
            "src/payments/view.py",
            "token: ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        ),
    ]:
        result.findings.append(
            Finding(
                title="t",
                severity=sev,
                scan_type=ScanType.SAST,
                tool="argus-languages",
                file=file,
                line=7,
                rule_id=f"rule-{sev.value}",
                description=desc,
                fix_guidance="Rotate the key and email maria.gonzalez@gmail.com",
            )
        )
    return AggregatedReport(target="/home/dev/acme/payments", results=[result]).to_dict()


def findings(r: dict) -> list[dict]:
    return [f for res in r["results"] for f in res["findings"]]


def test_masks_personal_data_and_secret_values() -> None:
    out = sanitize_report(report())
    text = json.dumps(out)
    for leaked in ("gmail.com", "AKIAIOSFODNN7EXAMPLE", "sk_live_51Hx", "ghp_abcdef"):
        assert leaked not in text
    assert out["sanitized"]["personal_data_masked"] >= 1
    assert out["sanitized"]["secret_values_masked"] == 3
    assert "fix_guidance" in findings(out)[0]  # nothing dropped unless asked


def test_keeps_actionable_fields() -> None:
    out = sanitize_report(report())
    f = next(x for x in findings(out) if x["rule_id"] == "rule-critical")
    assert (f["file"], f["line"], f["severity"]) == ("src/payments/keys.py", 7, "critical")


def test_hash_paths_is_stable_and_keeps_extension(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ARGUS_REDACTION_KEY", raising=False)
    a, b = sanitize_report(report(), hash_paths=True), sanitize_report(report(), hash_paths=True)
    files = [f["file"] for f in findings(a)]
    assert all(p.startswith("[path:") and p.endswith(".py") for p in files)
    assert files == [f["file"] for f in findings(b)]
    assert "acme" not in json.dumps(a)  # target paths are hashed too
    monkeypatch.setenv("ARGUS_REDACTION_KEY", "k")
    keyed = [f["file"] for f in findings(sanitize_report(report(), hash_paths=True))]
    assert keyed != files


def test_max_findings_keeps_most_severe_and_updates_summary() -> None:
    out = sanitize_report(report(), max_findings=2)
    assert sorted(f["severity"] for f in findings(out)) == ["critical", "high"]
    assert out["sanitized"]["findings_omitted"] == 2
    assert out["summary"]["total_findings"] == 2


def test_drop_fields_but_never_location() -> None:
    out = sanitize_report(report(), drop_fields=["fix_guidance", "description", "file", "line"])
    f = findings(out)[0]
    assert "fix_guidance" not in f and "description" not in f
    assert "file" in f and "line" in f
    assert out["sanitized"]["fields_dropped"] == ["fix_guidance", "description"]


@pytest.mark.parametrize(
    ("text", "masked"),
    [
        ('password = "correct-horse-battery"', 'password = "[REDACTED:SECRET]"'),
        ("{'client_secret': 'abcd1234efgh'}", "{'client_secret': '[REDACTED:SECRET]'}"),
        (
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
            "Bearer [REDACTED:SECRET]",
        ),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----",
            "[REDACTED:SECRET]",
        ),
        ("password_reset_url = build()", "password_reset_url = build()"),
        ('token = ""', 'token = ""'),
    ],
)
def test_mask_secret_values(text: str, masked: str) -> None:
    assert mask_secret_values(text)[0] == masked


@pytest.mark.asyncio
async def test_mcp_tool() -> None:
    from argus.server import _handle_sanitize_report

    out = json.loads(
        (
            await _handle_sanitize_report(
                {"scan_result_json": json.dumps(report()), "max_findings": 1}
            )
        )[0].text
    )
    assert len(findings(out)) == 1 and findings(out)[0]["severity"] == "critical"
    assert "gmail.com" not in json.dumps(out)
    bad = json.loads((await _handle_sanitize_report({"scan_result_json": "{not json"}))[0].text)
    assert "error" in bad
    wrong = json.loads((await _handle_sanitize_report({"scan_result_json": "{}"}))[0].text)
    assert "error" in wrong
