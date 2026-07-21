"""Tests for user-initiated fix application."""

from __future__ import annotations

import pytest

from argus.tools.fix import _autofix_available, apply_finding_fix


def test_secrets_never_autofix():
    assert _autofix_available("gitleaks", "secrets") is False


def test_sca_never_autofix():
    assert _autofix_available("trivy", "sca") is False


@pytest.mark.asyncio
async def test_apply_false_returns_guidance_only(tmp_path):
    file_path = tmp_path / "app.py"
    file_path.write_text("eval('1')\n")

    result = await apply_finding_fix(
        target=str(tmp_path),
        file=str(file_path),
        tool="semgrep",
        scan_type="sast",
        fix_guidance="Remove eval()",
        apply=False,
    )

    assert result["applied"] is False
    assert result["message"] == "Remove eval()"
    assert file_path.read_text() == "eval('1')\n"


@pytest.mark.asyncio
async def test_secrets_apply_blocked(tmp_path):
    file_path = tmp_path / "config.env"
    file_path.write_text("API_KEY=secret\n")

    result = await apply_finding_fix(
        target=str(tmp_path),
        file=str(file_path),
        tool="gitleaks",
        scan_type="secrets",
        fix_guidance="Rotate the key",
        apply=True,
    )

    assert result["applied"] is False
    assert "cannot be auto-fixed" in result["message"]
    assert file_path.read_text() == "API_KEY=secret\n"
