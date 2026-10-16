"""Tests for PCI-DSS scan tool wiring."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.models import ScanType
from argus.tools import pci
from argus.tools.pci import run_pci_scan


@pytest.mark.asyncio
async def test_run_pci_scan_finds_cvv_column(tmp_path: Path):
    model = tmp_path / "models.py"
    model.write_text("cvv = Column(String(4))\n")
    result = await run_pci_scan(str(tmp_path))
    assert result.scan_type == ScanType.PCI
    assert result.tool == "argus-pci"
    assert any(f.rule_id == "pci-cvv-storage" for f in result.findings)
    assert all(f.scan_type == ScanType.PCI for f in result.findings)


@pytest.mark.asyncio
async def test_run_pci_scan_finds_card_number_in_log(tmp_path: Path):
    src = tmp_path / "pay.py"
    src.write_text('logger.info("charging %s", card_number)\n')
    result = await run_pci_scan(str(tmp_path))
    assert any(f.rule_id == "pci-pan-in-logs" for f in result.findings)


@pytest.mark.asyncio
async def test_run_pci_scan_finds_card_data_over_http(tmp_path: Path):
    src = tmp_path / "client.js"
    src.write_text('fetch("http://payments.example.com/charge?card_number=" + pan)\n')
    result = await run_pci_scan(str(tmp_path))
    assert any(f.rule_id == "pci-http-card-data" for f in result.findings)


@pytest.mark.asyncio
async def test_run_pci_scan_clean_file(tmp_path: Path):
    src = tmp_path / "clean.py"
    src.write_text('def greet(name):\n    return f"hello {name}"\n')
    result = await run_pci_scan(str(tmp_path))
    assert result.findings == []
    assert result.errors == []


@pytest.mark.asyncio
async def test_run_pci_scan_loads_rules(tmp_path: Path):
    result = await run_pci_scan(str(tmp_path))
    assert result.metadata["rule_pack"] == "pci-dss"
    assert result.metadata["rules_loaded"] > 0


@pytest.mark.asyncio
async def test_run_pci_scan_reports_missing_rule_pack(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(pci, "load_rules_from_files", lambda names: [])
    result = await run_pci_scan(str(tmp_path))
    assert result.findings == []
    assert any("no PCI-DSS rules loaded" in e for e in result.errors)


@pytest.mark.asyncio
async def test_scan_pci_mcp_tool(tmp_path: Path):
    from argus.server import call_tool, list_tools

    assert "scan_pci" in {tool.name for tool in await list_tools()}
    (tmp_path / "pay.py").write_text('logger.info("charging %s", card_number)\n')
    result = await call_tool("scan_pci", {"target": str(tmp_path), "format": "json"})
    assert "pci-pan-in-logs" in result[0].text
