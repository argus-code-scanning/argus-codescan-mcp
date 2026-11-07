"""Upload scan results to the Argus cloud dashboard.

.. warning::
    This module is deprecated and will be removed in a future version.
    Use the :mod:`argus.cloud_upload` module instead.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from argus.models import counts_toward_failure

logger = logging.getLogger(__name__)

DEFAULT_API_URL = "http://localhost:4000/v1"
DEFAULT_FAIL_ON = "high"

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

# Upload redaction (on by default; ARGUS_UPLOAD_REDACT=0 disables it).
MAX_UPLOAD_MESSAGE_CHARS = 500
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD_RE = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")


class CloudConfig:
    """Cloud upload settings from environment variables."""

    def __init__(
        self,
        *,
        api_url: str,
        api_key: str,
        upload_script: str | None,
        fail_on: str,
        enabled: bool,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.upload_script = upload_script
        self.fail_on = fail_on
        self.enabled = enabled


def get_cloud_config() -> CloudConfig:
    """Read cloud upload configuration from environment."""
    api_key = os.environ.get("ARGUS_API_KEY", "").strip()
    api_url = os.environ.get("ARGUS_API_URL", DEFAULT_API_URL).strip() or DEFAULT_API_URL
    upload_script = os.environ.get("ARGUS_UPLOAD_SCRIPT", "").strip() or None
    fail_on = os.environ.get("ARGUS_FAIL_ON", DEFAULT_FAIL_ON).strip() or DEFAULT_FAIL_ON
    return CloudConfig(
        api_url=api_url,
        api_key=api_key,
        upload_script=upload_script,
        fail_on=fail_on,
        enabled=bool(api_key),
    )


def is_cloud_upload_enabled() -> bool:
    return get_cloud_config().enabled


def is_upload_redaction_enabled() -> bool:
    value = os.environ.get("ARGUS_UPLOAD_REDACT", "1").strip().lower()
    return value not in {"0", "false", "no", "off"}


def _luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def redact_pii(text: str) -> tuple[str, int]:
    """Redact emails, US SSNs and card numbers. Returns (text, redaction count)."""
    count = 0
    for pattern, label in ((_EMAIL_RE, "EMAIL"), (_SSN_RE, "SSN"), (_CARD_RE, "CARD")):

        def _replace(match: re.Match[str], label: str = label) -> str:
            nonlocal count
            if label == "CARD" and not _luhn_valid(re.sub(r"[ -]", "", match.group(0))):
                return match.group(0)
            count += 1
            return f"[REDACTED_{label}]"

        text = pattern.sub(_replace, text)
    return text, count


def strip_url_credentials(url: str) -> str:
    """Drop ``user:token@`` from URLs such as an authenticated git remote."""
    parts = urllib.parse.urlsplit(url)
    if not parts.scheme or "@" not in parts.netloc:
        return url
    host = parts.netloc.rsplit("@", 1)[1]
    return urllib.parse.urlunsplit(parts._replace(netloc=host))


def sanitize_for_upload(payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Redact PII in finding titles/messages and cap message length.

    Returns a new payload and the number of redactions made.
    """
    total = 0
    findings: list[dict[str, Any]] = []
    for finding in payload.get("findings", []):
        clean = dict(finding)
        for key in ("title", "message"):
            value = clean.get(key)
            if isinstance(value, str):
                clean[key], count = redact_pii(value)
                total += count
        message = clean.get("message")
        if isinstance(message, str) and len(message) > MAX_UPLOAD_MESSAGE_CHARS:
            clean["message"] = message[:MAX_UPLOAD_MESSAGE_CHARS] + "…"
        findings.append(clean)
    return {**payload, "findings": findings}, total


def scan_status(report_dict: dict[str, Any], fail_on: str) -> str:
    """Return ``passed`` or ``failed`` based on findings vs fail-on threshold."""
    if fail_on == "never":
        return "passed"
    threshold = _SEV_ORDER.get(fail_on, 99)
    for result in report_dict.get("results", []):
        for finding in result.get("findings", []):
            sev = finding.get("severity", "unknown")
            if _SEV_ORDER.get(sev, 99) <= threshold and counts_toward_failure(finding):
                return "failed"
    return "passed"


def build_upload_payload(
    report_dict: dict[str, Any],
    *,
    duration_sec: float,
    fail_on: str,
    scan_type: str,
    target: str | None = None,
) -> dict[str, Any]:
    """Build the JSON body expected by the cloud ingest API."""
    findings: list[dict[str, Any]] = []
    for result in report_dict.get("results", []):
        scanner = result.get("tool", "")
        for finding in result.get("findings", []):
            findings.append(
                {
                    "ruleId": finding.get("rule_id", ""),
                    "title": finding.get("title", ""),
                    "severity": finding.get("severity", "unknown"),
                    "file": finding.get("file", ""),
                    "line": finding.get("line", 0),
                    "scanner": scanner,
                    "message": finding.get("description", ""),
                }
            )

    git_meta = get_git_metadata(_resolve_git_root(target or report_dict.get("target", "")))

    payload: dict[str, Any] = {
        "status": scan_status(report_dict, fail_on),
        "failOn": fail_on,
        "durationSec": max(0, int(round(duration_sec))),
        "scanType": scan_type,
        "target": target or report_dict.get("target", ""),
        "findings": findings,
        **git_meta,
    }
    summary = report_dict.get("summary", {})
    if summary:
        payload["summary"] = summary
    return payload


def _resolve_git_root(target: str) -> Path:
    path = Path(target).expanduser()
    if path.is_file():
        path = path.parent
    elif not path.exists():
        path = Path.cwd()
    return path.resolve()


def get_git_metadata(cwd: Path | str) -> dict[str, str]:
    """Collect repo, branch, and commit from git (best effort)."""
    root = Path(cwd)

    def _git(*args: str) -> str:
        try:
            proc = subprocess.run(
                ["git", *args],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0:
                return proc.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
        return ""

    repo = strip_url_credentials(_git("remote", "get-url", "origin"))
    branch = _git("rev-parse", "--abbrev-ref", "HEAD")
    commit = _git("rev-parse", "HEAD")
    return {"repo": repo, "branch": branch, "commit": commit}


def _upload_via_http(payload: dict[str, Any], config: CloudConfig) -> str:
    url = f"{config.api_url}/scans"
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config.api_key}",
            "X-API-Key": config.api_key,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response_body = response.read().decode("utf-8", errors="replace")
            if response_body.strip():
                try:
                    data = json.loads(response_body)
                    run_id = data.get("id") or data.get("runId") or data.get("scanId")
                    if run_id:
                        return f"uploaded (id: {run_id})"
                except json.JSONDecodeError:
                    pass
            return "uploaded"
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"Cloud upload HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cloud upload failed: {exc.reason}") from exc


def _upload_via_script(payload: dict[str, Any], script_path: str) -> str:
    script = Path(script_path).expanduser()
    if not script.is_file():
        raise RuntimeError(f"ARGUS_UPLOAD_SCRIPT not found: {script}")

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(payload, handle)
        temp_path = handle.name

    try:
        proc = subprocess.run(
            ["node", str(script), temp_path],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "upload script failed").strip()[:300]
            raise RuntimeError(err)
        return "uploaded via script"
    finally:
        Path(temp_path).unlink(missing_ok=True)


async def upload_scan_report(
    report_dict: dict[str, Any],
    *,
    duration_sec: float,
    fail_on: str | None = None,
    scan_type: str = "unknown",
    target: str | None = None,
    force: bool = False,
) -> str | None:
    """Upload scan results when cloud credentials are configured.

    Returns a short status string on success, ``None`` when skipped.
    Raises on hard failures when upload was attempted.
    """
    config = get_cloud_config()
    if not config.enabled and not force:
        return None

    if not config.api_key:
        return None

    effective_fail_on = fail_on or config.fail_on
    payload = build_upload_payload(
        report_dict,
        duration_sec=duration_sec,
        fail_on=effective_fail_on,
        scan_type=scan_type,
        target=target,
    )
    if is_upload_redaction_enabled():
        payload, redactions = sanitize_for_upload(payload)
    else:
        redactions = 0
    logger.info(
        "Cloud upload: %d finding(s), %d redaction(s)", len(payload["findings"]), redactions
    )

    import asyncio

    if config.upload_script:
        return await asyncio.to_thread(_upload_via_script, payload, config.upload_script)
    return await asyncio.to_thread(_upload_via_http, payload, config)


class ScanTimer:
    """Simple monotonic timer for scan duration."""

    def __init__(self) -> None:
        self._start = time.monotonic()

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start
