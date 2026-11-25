"""`argus scan privacy`: GDPR/CCPA code patterns (#55)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus import cli
from argus.models import Severity
from argus.tools.privacy import DISCLAIMER, privacy_findings

GA = '<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC123"></script>\n'
PIXEL = "fbq('init', '1234567890');\n"
SCHEMA = """
model User {
  id    String @id
  email String @unique
  name  String
}

model Session {
  id        String   @id
  userId    String
  expiresAt DateTime
}

model Customer {
  id        String    @id
  email     String
  deletedAt DateTime?
}
"""


def write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)


def rules(root: Path) -> dict[str, list]:
    findings, _ = privacy_findings(str(root))
    out: dict[str, list] = {}
    for f in findings:
        out.setdefault(f.rule_id, []).append(f)
    return out


def test_trackers_without_consent(tmp_path: Path) -> None:
    write(tmp_path, {"public/index.html": GA, "src/track.js": PIXEL})
    found = rules(tmp_path)
    assert len(found["privacy-third-party-tracker"]) == 2
    consent = found["privacy-missing-consent-check"][0]
    assert consent.severity == Severity.MEDIUM and "2 tracker(s)" in consent.title
    assert DISCLAIMER in consent.description


def test_consent_manager_turns_trackers_into_notes(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "public/index.html": GA,
            "src/consent.js": "gtag('consent', 'default', { analytics_storage: 'denied' });\n",
        },
    )
    found = rules(tmp_path)
    assert "privacy-missing-consent-check" not in found
    assert found["privacy-third-party-tracker"][0].severity == Severity.INFO


def test_user_endpoints_without_deletion(tmp_path: Path) -> None:
    write(
        tmp_path,
        {"src/users.ts": "@Controller('users')\nexport class U {\n  @Get('me')\n  me() {}\n}\n"},
    )
    assert "privacy-no-data-deletion-endpoint" in rules(tmp_path)
    write(tmp_path, {"src/account.ts": "async deleteAccount(userId: string) { /* erase */ }\n"})
    assert "privacy-no-data-deletion-endpoint" not in rules(tmp_path)


def test_prisma_models_without_retention(tmp_path: Path) -> None:
    write(tmp_path, {"prisma/schema.prisma": SCHEMA})
    retention = rules(tmp_path)["privacy-retention-no-ttl"]
    assert [f.title.split()[1] for f in retention] == [
        "User"
    ]  # Session has expiresAt, Customer deletedAt


def test_non_eu_region_and_fingerprinting(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "src/storage.ts": "const s3 = new S3Client({ region: 'us-east-1' });\n",
            "src/fp.ts": "import FingerprintJS from '@fingerprintjs/fingerprintjs';\n",
            "src/eu.ts": "const s3 = new S3Client({ region: 'eu-west-2' });\n",
        },
    )
    found = rules(tmp_path)
    assert [f.file for f in found["privacy-non-eu-storage-region"]] == ["src/storage.ts"]
    assert "privacy-fingerprinting" in found


def test_pii_in_logs_is_included(tmp_path: Path) -> None:
    write(tmp_path, {"app.py": 'logger.info(f"login {user.email}")\n'})
    assert "pii-email-in-logs" in rules(tmp_path)


def test_clean_project(tmp_path: Path) -> None:
    write(tmp_path, {"src/app.ts": "export const add = (a: number, b: number) => a + b;\n"})
    assert rules(tmp_path) == {}


def test_cli_and_mcp(tmp_path: Path, capsys) -> None:
    write(tmp_path, {"public/index.html": GA})
    assert (
        cli.main(["scan", "privacy", str(tmp_path), "--format", "json", "--fail-on", "medium"]) == 1
    )
    report = json.loads(capsys.readouterr().out)
    assert any(
        f["rule_id"] == "privacy-missing-consent-check"
        for r in report["results"]
        for f in r["findings"]
    )


@pytest.mark.asyncio
async def test_mcp_scan_privacy(tmp_path: Path) -> None:
    from argus.server import _handle_scan_privacy

    write(tmp_path, {"public/index.html": GA})
    out = await _handle_scan_privacy({"target": str(tmp_path), "format": "json"})
    assert "privacy-missing-consent-check" in out[0].text
