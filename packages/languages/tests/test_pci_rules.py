"""Tests for PCI-DSS cardholder-data exposure rules."""

from pathlib import Path

from argus_languages.rules_loader import RULE_FILES, load_rules_from_files
from argus_languages.scanner import scan_path


def _scan_pci(path: Path):
    return scan_path(path, rules=load_rules_from_files(("pci-dss.yaml",)))


def _ids(result) -> set[str]:
    return {x.rule_id for x in result.findings}


def test_pci_cvv_storage(tmp_path: Path):
    f = tmp_path / "models.py"
    f.write_text("class Payment(Base):\n    cvv = Column(String(4))\n")
    assert "pci-cvv-storage" in _ids(_scan_pci(f))


def test_pci_cvv_storage_ignores_unrelated_code(tmp_path: Path):
    f = tmp_path / "models.py"
    f.write_text("class User(Base):\n    name = Column(String(50))\n")
    assert "pci-cvv-storage" not in _ids(_scan_pci(f))


def test_pci_pan_in_logs(tmp_path: Path):
    f = tmp_path / "pay.py"
    f.write_text('logger.info(f"charging card {card_number}")\n')
    assert "pci-pan-in-logs" in _ids(_scan_pci(f))


def test_pci_pan_in_logs_js(tmp_path: Path):
    f = tmp_path / "pay.js"
    f.write_text("console.log('card', cardNumber);\n")
    assert "pci-pan-in-logs" in _ids(_scan_pci(f))


def test_pci_pan_in_logs_ignores_comments(tmp_path: Path):
    f = tmp_path / "pay.py"
    f.write_text("# logger.info(card_number)  never log this\n")
    assert "pci-pan-in-logs" not in _ids(_scan_pci(f))


def test_pci_http_card_data(tmp_path: Path):
    f = tmp_path / "client.py"
    f.write_text('url = "http://pay.example.com/charge?card_number=" + n\n')
    assert "pci-http-card-data" in _ids(_scan_pci(f))


def test_pci_http_card_data_allows_https_and_localhost(tmp_path: Path):
    f = tmp_path / "client.py"
    f.write_text(
        'a = "https://pay.example.com/charge?card_number=" + n\n'
        'b = "http://localhost:8000/charge?card_number=" + n\n'
    )
    assert "pci-http-card-data" not in _ids(_scan_pci(f))


def _scan_pan(path: Path):
    return scan_path(path, rules=load_rules_from_files(("pci-pan.yaml",)))


def test_pci_pan_rule_not_in_default_rule_set(tmp_path: Path):
    # Without the Luhn check in argus scan pci this rule is too noisy for default scans.
    assert "pci-pan.yaml" not in RULE_FILES
    f = tmp_path / "billing.py"
    f.write_text('CARD = "4539148803436467"\n')
    assert "pci-pan-in-source" not in _ids(scan_path(f))


def test_pci_pan_in_source_marks_card_shaped_numbers(tmp_path: Path):
    f = tmp_path / "billing.py"
    f.write_text('CARD = "4539 1488 0343 6467"\nAMEX = "376124983304571"\n')
    findings = [x for x in _scan_pan(f).findings if x.rule_id == "pci-pan-in-source"]
    assert [x.line for x in findings] == [1, 2]


def test_pci_pan_in_source_ignores_other_numbers(tmp_path: Path):
    f = tmp_path / "ids.py"
    f.write_text("ts = 1700000000000\nshort = 453914880\nlong_id = 45391488034364671234\n")
    assert "pci-pan-in-source" not in _ids(_scan_pan(f))
