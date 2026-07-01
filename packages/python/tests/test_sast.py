"""Tests for SAST tool runners."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from argus.models import ScanType, Severity
from argus.tools.sast import run_bandit, run_semgrep


BANDIT_SAMPLE_OUTPUT = json.dumps(
    {
        "results": [
            {
                "test_name": "hardcoded_password_string",
                "test_id": "B105",
                "issue_severity": "HIGH",
                "issue_confidence": "MEDIUM",
                "issue_text": "Possible hardcoded password: 'secret123'",
                "filename": "app/config.py",
                "line_number": 15,
                "issue_cwe": {
                    "id": "259",
                    "link": "https://cwe.mitre.org/data/definitions/259.html",
                },
            }
        ],
        "metrics": {"_totals": {"nosec": 0, "skipped_tests": 0}},
    }
)

SEMGREP_SAMPLE_OUTPUT = json.dumps(
    {
        "results": [
            {
                "check_id": "python.flask.security.audit.hardcoded-config.hardcoded-config",
                "path": "app/app.py",
                "start": {"line": 20, "col": 5},
                "extra": {
                    "severity": "WARNING",
                    "message": "Hardcoded secret key detected",
                    "metadata": {
                        "cwe": ["CWE-798"],
                        "references": ["https://owasp.org"],
                    },
                },
            }
        ],
        "errors": [],
    }
)


@pytest.mark.asyncio
async def test_bandit_not_installed():
    with patch("argus.tools.sast.is_tool_available", return_value=False):
        result = await run_bandit("/some/path")
    assert not result.tool_available
    assert result.errors


@pytest.mark.asyncio
async def test_bandit_parses_output():
    with (
        patch("argus.tools.sast.is_tool_available", return_value=True),
        patch("argus.tools.sast.run_command", new_callable=AsyncMock) as mock_cmd,
    ):
        mock_cmd.return_value = (0, BANDIT_SAMPLE_OUTPUT, "")
        result = await run_bandit("/app")

    assert result.tool == "bandit"
    assert result.scan_type == ScanType.SAST
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.HIGH
    assert f.file == "app/config.py"
    assert f.line == 15
    assert "hardcoded_password_string" in f.title


@pytest.mark.asyncio
async def test_semgrep_not_installed():
    with patch("argus.tools.sast.is_tool_available", return_value=False):
        result = await run_semgrep("/some/path")
    assert not result.tool_available


@pytest.mark.asyncio
async def test_semgrep_parses_output():
    with (
        patch("argus.tools.sast.is_tool_available", return_value=True),
        patch("argus.tools.sast.run_command", new_callable=AsyncMock) as mock_cmd,
    ):
        mock_cmd.return_value = (0, SEMGREP_SAMPLE_OUTPUT, "")
        result = await run_semgrep("/app")

    assert result.tool == "semgrep"
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.MEDIUM  # WARNING maps to MEDIUM
    assert f.file == "app/app.py"
    assert f.line == 20
