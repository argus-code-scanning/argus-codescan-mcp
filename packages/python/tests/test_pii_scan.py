"""`argus scan pii` / MCP scan_pii (#52)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus import cli
from argus.models import Severity
from argus.tools.pii import run_pii_scan


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        'CONTACT = {"email": "maria.gonzalez@gmail.com", "ssn": "219-09-9999"}\n'
        'SAMPLE = {"email": "jane@example.com"}\n'
        'logger.info(f"user {user.email} signed in")\n'
    )
    data = tmp_path / "data"
    data.mkdir()
    (data / "customers.json").write_text(
        '[\n  {"first_name": "Margaret", "phone": "+44 7700 912345"},\n  {"first_name": "John"}\n]\n'
    )
    exports = tmp_path / "exports"
    exports.mkdir()
    (exports / "payments.csv").write_text(
        "name,card\nMargaret,4539 1488 0343 6467\nsample,4111 1111 1111 1111\n"
    )
    (tmp_path / ".env").write_text("ADMIN_EMAIL='olu.adebayo@gmail.com'\n")
    (tmp_path / "package-lock.json").write_text('{"email": "maintainer@gmail.com"}\n')
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "data.yaml").write_text(
        'ssn: "219-09-9999"\nfirst_name: "Margaret"\nemail: "maria.gonzalez@gmail.com"\n'
    )
    return tmp_path


@pytest.mark.asyncio
async def test_scan_finds_code_and_data_file_pii(project: Path) -> None:
    result = await run_pii_scan(str(project))
    found = {(f.file, f.rule_id): f for f in result.findings}
    assert ("app.py", "pii-hardcoded-email") in found
    assert ("app.py", "pii-hardcoded-ssn") in found
    assert ("app.py", "pii-email-in-logs") in found  # existing logging rule runs too
    assert ("data/customers.json", "pii-hardcoded-name") in found
    assert ("data/customers.json", "pii-hardcoded-phone") in found
    assert ("exports/payments.csv", "pci-pan-in-source") in found  # Luhn-valid card
    assert (".env", "pii-hardcoded-email") in found
    assert not any(f.file == "package-lock.json" for f in result.findings)
    # In tests only ID numbers are reported (one level lower); sample names/emails are counted.
    assert found[("tests/data.yaml", "pii-hardcoded-ssn")].severity == Severity.MEDIUM
    assert not [
        f
        for f in result.findings
        if f.file == "tests/data.yaml" and f.rule_id != "pii-hardcoded-ssn"
    ]
    assert result.metadata["skipped_in_tests_and_docs"] == 2
    assert found[("app.py", "pii-hardcoded-ssn")].severity == Severity.HIGH
    # The well-known test card and example.com address are ignored.
    emails = [f for f in result.findings if f.rule_id == "pii-hardcoded-email"]
    assert len(emails) == 2
    assert sum(f.rule_id == "pci-pan-in-source" for f in result.findings) == 1
    assert all(
        f.tool == "argus-pii" and f.data_classification in {"pii", "pci"} for f in result.findings
    )


def test_cli_scan_pii(project: Path, capsys) -> None:
    code = cli.main(["scan", "pii", str(project), "--format", "json", "--fail-on", "high"])
    report = json.loads(capsys.readouterr().out)
    assert any(
        f["rule_id"] == "pii-hardcoded-ssn" for r in report["results"] for f in r["findings"]
    )
    assert code == 1


@pytest.mark.asyncio
async def test_mcp_scan_pii(project: Path) -> None:
    from argus.server import _handle_scan_pii

    out = await _handle_scan_pii({"target": str(project), "format": "json"})
    assert "pii-hardcoded-email" in out[0].text
