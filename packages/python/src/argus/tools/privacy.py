"""`argus scan privacy`: GDPR / CCPA style code patterns (#55).

Argus finds code patterns, not legal compliance. Every finding says "review this"; no
findings is not a compliance statement.

- Line rules: ``privacy-gdpr.yaml`` (trackers, non-EU storage, fingerprinting) and
  ``pii.yaml`` (personal data in logs, prints, errors and monitoring tools).
- Project-level checks (things that are *missing*):
  * trackers with no consent mechanism anywhere in the project,
  * user/account endpoints with no way to delete, anonymise or export a user's data,
  * Prisma models holding personal data with no deletion / expiry field.
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from argus_languages.noise import path_context
from argus_languages.rules_loader import load_rules_from_files
from argus_languages.scanner import scan_path as _scan_path

from argus.models import Finding, ScanResult, ScanType, Severity
from argus.tools.abuse_controls import _MANIFESTS, _SKIP_DIRS, _SOURCE_SUFFIXES, find_endpoints
from argus.tools.pci import _SEV_MAP

TOOL = "argus-privacy"
RULE_FILES = ("privacy-gdpr.yaml", "pii.yaml")
DISCLAIMER = "Code pattern, not a legal assessment: review with whoever owns privacy compliance."
_SUFFIXES = _SOURCE_SUFFIXES | {
    ".html",
    ".htm",
    ".vue",
    ".svelte",
    ".prisma",
    ".erb",
    ".ejs",
    ".hbs",
}
_MAX_FILE = 1024 * 1024

_CONSENT_EVIDENCE = re.compile(
    r"cookiebot|onetrust|optanon|osano|klaro|cookieconsent|cookie-consent|vanilla-cookieconsent"
    r"|usercentrics|iubenda|termly|didomi|quantcast\s*choice|consentmanager|cookieyes|complianz"
    r"|tarteaucitron|react-cookie-consent|@cookie-consent|cookie_consent|cookieConsent|hasConsent"
    r"|gtag\(\s*['\"]consent['\"]|ad_storage|analytics_storage|consent_?mode|trackingConsent"
    r"|posthog\.opt_(?:in|out)_capturing|opt_out_capturing_by_default|optOut\(|mixpanel\.opt_(?:in|out)",
    re.IGNORECASE,
)
_USER_ROUTE = re.compile(
    r"/(?:users?|accounts?|profiles?|me|members?|customers?|patients?)\b", re.I
)
_DELETION_EVIDENCE = re.compile(
    r"delete_?(?:my_?)?(?:account|user|profile|me)|deleteAccount|deleteUser|removeUser|deleteProfile"
    r"|close_?account|closeAccount|anonymi[sz]e|pseudonymi[sz]e|erase_?(?:user|data|account)|eraseUser"
    r"|right_?to_?(?:be_?forgotten|erasure)|gdpr|data_?export|exportData|export_?user|exportUser"
    r"|download_?(?:my_?)?data|dataPortability|data_?portability|purge_?user|softDelete|soft_delete"
    # Route-level deletes count only on user/account/profile/me paths (deleting an API key or a
    # post isn't deleting a person's data).
    r"|@Delete\(\s*['\"](?:me|account|profile|users?/[^'\"]*)['\"]"
    r"|(?:router|app|r)\.delete\(\s*['\"][^'\"]*/(?:users?|accounts?|profiles?|me)\b"
    r"|\.(?:Delete|DELETE)\(\s*\"[^\"]*/(?:users?|accounts?|profiles?|me)\b"
    r"|(?:HttpDelete|DeleteMapping)\(\s*\"[^\"]*(?:users?|accounts?|profiles?|me)\b",
    re.IGNORECASE,
)
_PRISMA_MODEL = re.compile(r"^model\s+(\w+)\s*\{(.*?)^\}", re.M | re.S)
_PII_FIELD = re.compile(
    r"^\s*(?:email|phone(?:Number)?|firstName|lastName|fullName|address|dateOfBirth|dob|ssn"
    r"|nationalId|passport\w*|ipAddress)\s+String",
    re.M | re.I,
)
# A bare `name` is personal only on models that describe people (not Organization, Product…).
_PERSON_MODEL = re.compile(
    r"^(?:User|Users|Account|Customer|Client|Member|Person|People|Contact|Lead|Patient|Employee"
    r"|Student|Applicant|Candidate|Subscriber|Profile|Guest|Visitor|Worker|Staff|Parent|Child)$",
    re.I,
)
_NAME_FIELD = re.compile(r"^\s*name\s+String", re.M)
_RETENTION_FIELD = re.compile(
    r"^\s*(?:deleted_?at|deletedAt|expires_?at|expiresAt|expiry|retain_?until|retainUntil|retention\w*"
    r"|purge_?at|purgeAt|anonymi[sz]ed_?at|anonymi[sz]edAt|ttl|archivedAt|archived_at)\b",
    re.M | re.I,
)


@dataclass
class Evidence:
    consent: str | None = None
    deletion: str | None = None
    user_routes: list[str] = field(default_factory=list)
    prisma_models: list[tuple[str, str, int]] = field(default_factory=list)  # name, file, line


def _files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() in _SUFFIXES or name in _MANIFESTS:
                out.append(path)
    return out


def collect(root: Path) -> Evidence:
    base = root if root.is_dir() else root.parent
    ev = Evidence()
    for path in _files(root):
        rel = path.relative_to(base).as_posix() if path != base else path.name
        if path_context(rel):
            continue
        try:
            if path.stat().st_size > _MAX_FILE:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if ev.consent is None and (m := _CONSENT_EVIDENCE.search(text)):
            ev.consent = f"{rel}:{text.count(chr(10), 0, m.start()) + 1}"
        if ev.deletion is None and (m := _DELETION_EVIDENCE.search(text)):
            ev.deletion = f"{rel}:{text.count(chr(10), 0, m.start()) + 1}"
        for e in find_endpoints(text, rel):
            if _USER_ROUTE.search(e.path):
                ev.user_routes.append(f"{e.path} ({e.file}:{e.line})")
        if path.suffix == ".prisma":
            for m in _PRISMA_MODEL.finditer(text):
                body = m.group(2)
                personal = _PII_FIELD.search(body) or (
                    _PERSON_MODEL.match(m.group(1)) and _NAME_FIELD.search(body)
                )
                if personal and not _RETENTION_FIELD.search(body):
                    ev.prisma_models.append((m.group(1), rel, text.count("\n", 0, m.start()) + 1))
    return ev


def _finding(
    rule_id: str,
    title: str,
    severity: Severity,
    file: str,
    line: int,
    detail: str,
    fix: str,
    *,
    cwe: str = "CWE-359",
    confidence: str = "low",
    context: str = "",
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        scan_type=ScanType.SAST,
        tool=TOOL,
        file=file,
        line=line,
        rule_id=rule_id,
        description=f"{detail} {DISCLAIMER}".strip(),
        fix_guidance=fix,
        cwe=cwe,
        data_classification="pii",
        confidence=confidence,
        context=context,
        references=["https://gdpr-info.eu/", "https://oag.ca.gov/privacy/ccpa"],
    )


def privacy_findings(target: str) -> tuple[list[Finding], dict[str, object]]:
    rules = load_rules_from_files(RULE_FILES)
    native = _scan_path(target, rules=rules)
    ev = collect(Path(target))
    findings: list[Finding] = []
    trackers = [f for f in native.findings if f.rule_id == "privacy-third-party-tracker"]

    for item in native.findings:
        severity = _SEV_MAP.get(item.severity, Severity.INFO)
        detail = item.description or ""
        if item.rule_id == "privacy-third-party-tracker" and ev.consent:
            severity = Severity.INFO
            detail = (
                f"A consent mechanism was found ({ev.consent}); check this tracker waits for it."
            )
        findings.append(
            _finding(
                item.rule_id,
                item.title,
                severity,
                item.file,
                item.line,
                detail,
                getattr(item, "fix_guidance", "") or "",
                cwe="CWE-532" if "log" in item.rule_id else "CWE-359",
                confidence=getattr(item, "confidence", "") or "medium",
                context=getattr(item, "context", ""),
            )
        )

    prod_trackers = [t for t in trackers if not getattr(t, "context", "")]
    if prod_trackers and not ev.consent:
        first = prod_trackers[0]
        findings.append(
            _finding(
                "privacy-missing-consent-check",
                f"{len(prod_trackers)} tracker(s) and no consent mechanism found in the project",
                Severity.MEDIUM,
                first.file,
                first.line,
                "Analytics and ad trackers set cookies or identify visitors, which needs prior "
                "consent in the EU/UK (GDPR, ePrivacy) and an opt-out under CCPA. No consent "
                "manager or consent-mode call was found anywhere in the code.",
                "Add a consent manager (Cookiebot, OneTrust, Klaro, cookieconsent…) or Google "
                "Consent Mode, and load trackers only after consent. A consent banner that lives "
                "outside this repository (tag manager, CMS) is fine; then ignore this finding.",
                confidence="medium",
            )
        )

    if ev.user_routes and not ev.deletion:
        where = ev.user_routes[0]
        m = re.search(r"\((.+):(\d+)\)$", where)
        findings.append(
            _finding(
                "privacy-no-data-deletion-endpoint",
                "User/account endpoints but no way to delete, anonymise or export a user's data — review",
                Severity.LOW,
                m.group(1) if m else "",
                int(m.group(2)) if m else 0,
                "People can ask for their data to be erased or exported (GDPR Art. 15, 17, 20; "
                f"CCPA right to delete). Endpoints: {', '.join(ev.user_routes[:5])}"
                + (f" and {len(ev.user_routes) - 5} more." if len(ev.user_routes) > 5 else "."),
                "Provide account deletion (or anonymisation) and a data export, in the app or as "
                "a documented support process. If that already happens elsewhere, ignore this.",
            )
        )

    for name, file, line in ev.prisma_models[:20]:
        findings.append(
            _finding(
                "privacy-retention-no-ttl",
                f"Model {name} stores personal data with no deletion or expiry field — review retention",
                Severity.LOW,
                file,
                line,
                "GDPR's storage limitation means personal data should be deleted or anonymised "
                "when it's no longer needed. The model has no deletedAt / expiresAt / retention "
                "field, which usually means nothing removes old records.",
                "Decide how long you keep these records, add deletedAt / expiresAt (or a scheduled "
                "purge job) and document the retention period.",
            )
        )

    metadata: dict[str, object] = {
        "rule_pack": "privacy-gdpr",
        "consent_evidence": ev.consent,
        "deletion_evidence": ev.deletion,
        "user_endpoints": len(ev.user_routes),
        "disclaimer": DISCLAIMER,
        **native.metadata,
    }
    return findings, metadata


async def run_privacy_scan(target: str) -> ScanResult:
    result = ScanResult(tool=TOOL, scan_type=ScanType.SAST, target=target)
    try:
        findings, metadata = await asyncio.to_thread(privacy_findings, target)
    except Exception as exc:
        result.errors.append(f"argus-privacy error: {exc}")
        return result
    result.findings.extend(findings)
    result.metadata.update(metadata)
    return result
