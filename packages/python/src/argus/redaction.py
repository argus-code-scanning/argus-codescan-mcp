"""Redact personal data from scan output (#53).

Scanners stay raw; redaction runs once, where a report is turned into output that leaves the
developer's machine (SARIF, MCP responses, cloud upload) or wherever the user asks for it.

Masked values become ``[REDACTED:EMAIL]``. With ``ARGUS_REDACTION_KEY`` set they become
``[REDACTED:EMAIL:1a2b3c4d]``: an HMAC of the value, so the same value gets the same tag
across runs and auditors can correlate findings. There is no unkeyed hash on purpose: SSNs,
phone and card numbers are so few that a plain hash is reversed by trying them all.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Any

from argus.utils import luhn_valid

# Starts only at the beginning of a run of address characters, so a long dotted run is scanned
# once instead of once per position (#265: that took 1.5 s on 40,000 characters). No length caps:
# an over-long address must still be masked.
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
)
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_NINO = re.compile(r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b")
_CARD = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")
# International (+44 7700 900123) or separated national numbers ((415) 555-2671, 020 7946 0958).
# Needs a + or separators, so plain integers (line numbers, ids, versions) aren't touched.
_PHONE = re.compile(
    r"(?<![\w.])(?<!\d[\s.-])"  # not inside a longer run of digit groups (card numbers, ids)
    r"(?:\+\d{1,3}[\s.-]?\d{2,5}[\s.-]?\d{3,8}"  # international: +44 7700 912345
    r"|(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?|\d{2,4}[\s.-])\d{3,4}[\s.-]\d{3,4})"
    r"(?![\s.-]?\d)"
)

KINDS = ("EMAIL", "SSN", "NINO", "CARD", "PHONE")
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("EMAIL", _EMAIL),
    ("CARD", _CARD),  # before PHONE/SSN: card groups would otherwise look like them
    ("SSN", _SSN),
    ("NINO", _NINO),
    ("PHONE", _PHONE),
)

# Finding fields that describe *where* and *what*, never contain personal data, and that
# tools need intact (SARIF locations, fingerprints, policy matching).
STRUCTURAL_FIELDS = frozenset(
    {
        "file",
        "line",
        "column",
        "rule_id",
        "tool",
        "severity",
        "scan_type",
        "cwe",
        "cve",
        "package",
        "version",
        "context",
        "confidence",
        "data_classification",
        "dependency_paths",
        "references",
    }
)


def _tag(kind: str, value: str, key: bytes | None) -> str:
    if not key:
        return f"[REDACTED:{kind}]"
    digest = hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:8]
    return f"[REDACTED:{kind}:{digest}]"


def redaction_key() -> bytes | None:
    value = os.environ.get("ARGUS_REDACTION_KEY", "")
    return value.encode() if value else None


def redact_text(
    text: str,
    *,
    key: bytes | None = None,
    style: str = "tag",
    kinds: tuple[str, ...] = KINDS,
) -> tuple[str, int]:
    """Mask personal data in ``text``. Returns (text, number of values masked).

    ``style="upload"`` keeps the cloud upload format (``[REDACTED_EMAIL]``).
    """
    count = 0
    for kind, pattern in _PATTERNS:
        if kind not in kinds:
            continue

        def replace(match: re.Match[str], kind: str = kind) -> str:
            nonlocal count
            value = match.group(0)
            if kind == "CARD" and not luhn_valid(re.sub(r"[ -]", "", value)):
                return value
            count += 1
            return f"[REDACTED_{kind}]" if style == "upload" else _tag(kind, value, key)

        text = pattern.sub(replace, text)
    return text, count


def _limit_lines(text: str, max_lines: int) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    return (
        "\n".join(lines[:max_lines])
        + f"\n… ({len(lines) - max_lines} more line(s) hidden by data_policy)"
    )


def _clean(value: Any, *, pii: bool, key: bytes | None, max_lines: int | None) -> tuple[Any, int]:
    if isinstance(value, str):
        count = 0
        if pii:
            value, count = redact_text(value, key=key)
        if max_lines is not None:
            value = _limit_lines(value, max_lines)
        return value, count
    if isinstance(value, dict):
        total = 0
        out: dict[str, Any] = {}
        for k, v in value.items():
            out[k], n = _clean(v, pii=pii, key=key, max_lines=max_lines)
            total += n
        return out, total
    if isinstance(value, list):
        total = 0
        items = []
        for v in value:
            cleaned, n = _clean(v, pii=pii, key=key, max_lines=max_lines)
            items.append(cleaned)
            total += n
        return items, total
    return value, 0


def redact_report(
    report: dict[str, Any],
    *,
    pii: bool = True,
    max_snippet_lines: int | None = None,
    exclude_fields: tuple[str, ...] | list[str] = (),
) -> tuple[dict[str, Any], int]:
    """A copy of an Argus report dict with personal data masked in every finding's text.

    Locations, rule ids and severities are left alone; ``exclude_fields`` are dropped from
    each finding; long text (code excerpts, raw tool output) can be cut to ``max_snippet_lines``.
    """
    key = redaction_key()
    drop = {f for f in exclude_fields if f not in {"file", "line", "rule_id", "severity", "tool"}}
    total = 0
    results = []
    for result in report.get("results", []):
        findings = []
        for finding in result.get("findings", []):
            clean: dict[str, Any] = {}
            for name, value in finding.items():
                if name in drop:
                    continue
                if name in STRUCTURAL_FIELDS:
                    clean[name] = value
                    continue
                clean[name], n = _clean(value, pii=pii, key=key, max_lines=max_snippet_lines)
                total += n
            findings.append(clean)
        results.append({**result, "findings": findings})
    out = {**report, "results": results}
    if total:
        out["redactions"] = total
    return out, total
