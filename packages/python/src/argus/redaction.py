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


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Secret values that can appear in finding text (code excerpts, scanner messages).
_SECRET_TOKENS = re.compile(
    r"\bAKIA[0-9A-Z]{16}\b"  # AWS access key id
    r"|\bgh[pousr]_[A-Za-z0-9]{36,}\b"  # GitHub tokens
    r"|\bxox[abposr]-[A-Za-z0-9-]{10,}\b"  # Slack
    r"|\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b"  # Stripe
    r"|\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"  # JWT
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"
)
# name = "value" where the name says it's a secret; the value is replaced, the name kept.
_SECRET_ASSIGNMENT = re.compile(
    r"""((?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)"""
    r"""["']?\s*[:=]\s*)(["'])(?!\[REDACTED)([^"'\n]{4,})\2""",
    re.IGNORECASE,
)


def mask_secret_values(text: str) -> tuple[str, int]:
    """Replace secret values in free text. Returns (text, number masked)."""
    count = 0

    def token(_: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return "[REDACTED:SECRET]"

    def assignment(m: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return f"{m.group(1)}{m.group(2)}[REDACTED:SECRET]{m.group(2)}"

    text = _SECRET_TOKENS.sub(token, text)
    text = _SECRET_ASSIGNMENT.sub(assignment, text)
    return text, count


def _path_tag(path: str, key: bytes | None) -> str:
    """Stable stand-in for a file path that keeps the extension (``[path:1a2b3c4d].py``)."""
    if not path:
        return path
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    ext = name[name.rfind(".") :] if "." in name[1:] else ""
    if key:
        digest = hmac.new(key, path.encode(), hashlib.sha256).hexdigest()[:8]
    else:
        digest = hashlib.sha256(path.encode()).hexdigest()[:8]
    return f"[path:{digest}]{ext}"


def sanitize_report(
    report: dict[str, Any],
    *,
    redact_pii: bool = True,
    hash_paths: bool = False,
    max_findings: int | None = None,
    drop_fields: tuple[str, ...] | list[str] = (),
) -> dict[str, Any]:
    """A copy of a report that is safe to paste into an AI chat or a ticket (#59).

    Masks personal data and echoed secret values, optionally replaces file paths with stable
    tags, keeps only the most severe ``max_findings`` findings, and drops ``drop_fields``.
    Line numbers, rule ids and severities are kept so findings stay actionable.
    """
    from argus.utils import refresh_report_summary

    out, masked = redact_report(report, pii=redact_pii, exclude_fields=drop_fields)
    key = redaction_key()
    secrets_masked = 0
    for result in out.get("results", []):
        if hash_paths and result.get("target"):
            result["target"] = _path_tag(str(result["target"]), key)
        for finding in result.get("findings", []):
            for name, value in list(finding.items()):
                if isinstance(value, str) and name not in STRUCTURAL_FIELDS:
                    finding[name], n = mask_secret_values(value)
                    secrets_masked += n
            if hash_paths and finding.get("file"):
                finding["file"] = _path_tag(str(finding["file"]), key)

    omitted = 0
    if max_findings is not None and max_findings >= 0:
        ranked = sorted(
            (
                (_SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 5), r_i, f_i)
                for r_i, r in enumerate(out.get("results", []))
                for f_i, f in enumerate(r.get("findings", []))
            )
        )
        keep = {(r_i, f_i) for _, r_i, f_i in ranked[:max_findings]}
        omitted = len(ranked) - len(keep)
        for r_i, r in enumerate(out.get("results", [])):
            r["findings"] = [f for f_i, f in enumerate(r.get("findings", [])) if (r_i, f_i) in keep]

    if hash_paths and out.get("target"):
        out["target"] = _path_tag(str(out["target"]), key)
    out.pop("redactions", None)
    refresh_report_summary(out)
    out["sanitized"] = {
        "personal_data_masked": masked,
        "secret_values_masked": secrets_masked,
        "paths_hashed": hash_paths,
        "findings_omitted": omitted,
        "fields_dropped": [
            f for f in drop_fields if f not in {"file", "line", "rule_id", "severity", "tool"}
        ],
    }
    return out
