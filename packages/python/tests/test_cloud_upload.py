"""Tests for cloud dashboard upload."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from argus.cloud_upload import (
    build_upload_payload,
    get_cloud_config,
    is_cloud_upload_enabled,
    scan_status,
)


def test_cloud_disabled_without_api_key(monkeypatch):
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)
    assert is_cloud_upload_enabled() is False
    assert get_cloud_config().enabled is False


def test_cloud_enabled_with_api_key(monkeypatch):
    monkeypatch.setenv("ARGUS_API_KEY", "arg_live_test")
    monkeypatch.setenv("ARGUS_API_URL", "http://localhost:4000/v1")
    config = get_cloud_config()
    assert config.enabled is True
    assert config.api_url == "http://localhost:4000/v1"


def test_scan_status_failed_on_high():
    report = {
        "results": [
            {
                "tool": "semgrep",
                "findings": [{"severity": "medium", "rule_id": "x"}],
            }
        ]
    }
    assert scan_status(report, "high") == "passed"

    report["results"][0]["findings"].append({"severity": "high", "rule_id": "y"})
    assert scan_status(report, "high") == "failed"


def test_build_upload_payload_maps_findings():
    report = {
        "target": "/tmp/project",
        "summary": {"total_findings": 1},
        "results": [
            {
                "tool": "bandit",
                "findings": [
                    {
                        "rule_id": "B101",
                        "title": "assert_used",
                        "severity": "low",
                        "file": "app.py",
                        "line": 10,
                        "description": "Use of assert",
                    }
                ],
            }
        ],
    }

    with patch("argus.cloud_upload.get_git_metadata", return_value={"repo": "r", "branch": "b", "commit": "c"}):
        payload = build_upload_payload(
            report,
            duration_sec=3.6,
            fail_on="high",
            scan_type="sast",
        )

    assert payload["status"] == "passed"
    assert payload["durationSec"] == 4
    assert payload["scanType"] == "sast"
    assert payload["repo"] == "r"
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["scanner"] == "bandit"
    assert payload["findings"][0]["ruleId"] == "B101"


@pytest.mark.asyncio
async def test_upload_skipped_without_key(monkeypatch):
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)
    from argus.cloud_upload import upload_scan_report

    result = await upload_scan_report({"results": []}, duration_sec=1.0)
    assert result is None
