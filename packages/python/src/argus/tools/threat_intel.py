"""Known indicators of compromise (IOCs) in a repository (#181).

Matches URLs, domains, IPs and file hashes found in the target against:

- a local IOC list: ``.argus/iocs.txt`` in the target, or the file named by ``ARGUS_IOC_FILE``
  (one value per line: URL, domain, IPv4 or SHA-256; ``#`` comments allowed), and
- abuse.ch feeds (ThreatFox, URLhaus, MalwareBazaar) when ``ARGUS_ABUSECH_AUTH_KEY`` is set.
  abuse.ch requires a free Auth-Key for downloads. Feeds are cached under
  ``~/.cache/argus/threat-intel`` (``ARGUS_CACHE_DIR``) and refreshed after 24 hours
  (``ARGUS_IOC_MAX_AGE_HOURS``). With ``--no-network`` / ``ARGUS_NO_NETWORK`` only the cache is used.

Repository content never leaves the machine: feeds are downloaded and matched locally.
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import ipaddress
import logging
import os
import re
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from argus.models import Finding, ScanResult, ScanType, Severity

logger = logging.getLogger(__name__)

TOOL_NAME = "argus-threat-intel"
FEEDS: dict[str, tuple[str, str]] = {
    # name: (download URL template, homepage). Auth-Key goes in the path.
    "ThreatFox": (
        "https://threatfox-api.abuse.ch/v2/files/exports/{key}/full.csv.zip",
        "https://threatfox.abuse.ch/",
    ),
    "URLhaus": (
        "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv",
        "https://urlhaus.abuse.ch/",
    ),
    "MalwareBazaar": (
        "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv",
        "https://bazaar.abuse.ch/",
    ),
}
_MAX_DOWNLOAD = 300 * 1024 * 1024
_MAX_TEXT_FILE = 2 * 1024 * 1024
_MAX_HASHED_FILE = 50 * 1024 * 1024
_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        ".next",
        "target",
        "coverage",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
    }
)
_BINARY_SUFFIXES = frozenset(
    {
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".elf",
        ".jar",
        ".zip",
        ".tgz",
        ".gz",
        ".whl",
        ".node",
        ".msi",
        ".scr",
        ".apk",
        ".dmg",
        ".pkg",
        ".deb",
        ".rpm",
        ".7z",
        ".rar",
        ".lnk",
    }
)
# Big shared platforms appear in IOC feeds as *URLs* (a malicious file on GitHub, a Discord CDN
# link), never as whole malicious domains. Only exact-URL matches count for them.
_PLATFORM_DOMAINS = frozenset(
    {
        "github.com",
        "githubusercontent.com",
        "gitlab.com",
        "bitbucket.org",
        "google.com",
        "googleapis.com",
        "googleusercontent.com",
        "microsoft.com",
        "live.com",
        "office.com",
        "sharepoint.com",
        "onedrive.com",
        "dropbox.com",
        "amazonaws.com",
        "cloudfront.net",
        "azureedge.net",
        "windows.net",
        "discord.com",
        "discordapp.com",
        "discordapp.net",
        "telegram.org",
        "npmjs.org",
        "npmjs.com",
        "pypi.org",
        "pythonhosted.org",
        "cloudflare.com",
        "pages.dev",
        "workers.dev",
        "vercel.app",
        "netlify.app",
        "herokuapp.com",
        "mediafire.com",
        "pastebin.com",
        "transfer.sh",
        "docs.google.com",
        "drive.google.com",
    }
)

_URL_RE = re.compile(r"""\bhttps?://[^\s"'<>()\[\]{}`\\]+""", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


@dataclass(frozen=True)
class IOC:
    kind: str  # url | domain | ip | sha256
    value: str
    source: str
    family: str = ""
    first_seen: str = ""


def network_disabled() -> bool:
    return os.environ.get("ARGUS_NO_NETWORK", "").strip().lower() in {"1", "true", "yes"}


def _normalise_url(url: str) -> str:
    url = url.strip().rstrip(".,;")
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        port = f":{parts.port}" if parts.port else ""
    except ValueError:  # e.g. "http://localhost:3000,http://..." in a config string
        return url.lower()
    path = parts.path.rstrip("/") or ""
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme.lower()}://{host}{port}{path}{query}"


def classify(value: str) -> IOC | None:
    """An IOC from a bare value (local list or a feed cell), or None."""
    value = value.strip().strip('"').strip()
    if not value or value.startswith("#"):
        return None
    if value.lower().startswith(("http://", "https://")):
        return IOC("url", _normalise_url(value), "")
    if _SHA256_RE.match(value):
        return IOC("sha256", value.lower(), "")
    host = value.split(":", 1)[0] if value.count(":") == 1 else value  # ip:port / domain:port
    try:
        ipaddress.IPv4Address(host)
        return IOC("ip", host, "")
    except ValueError:
        pass
    if _DOMAIN_RE.fullmatch(host):
        return IOC("domain", host.lower().rstrip("."), "")
    return None


# ── Feed parsing ──────────────────────────────────────────────────────────────

_VALUE_COLUMNS = ("ioc_value", "ioc", "url", "sha256_hash", "sha256")
_FAMILY_COLUMNS = ("malware_printable", "malware", "signature", "threat")
_DATE_COLUMNS = ("first_seen_utc", "first_seen", "dateadded", "date_added")


def parse_feed(text: str, source: str) -> list[IOC]:
    """Parse an abuse.ch CSV export.

    The exports start with ``#`` comment lines, the last of which usually names the columns.
    Columns are looked up by name, so added or reordered columns don't break parsing. Rows
    without a usable header fall back to the first cell that looks like an IOC.
    """
    header: list[str] | None = None
    data_lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("#"):
            candidate = next(csv.reader([line.lstrip("#").strip()]), [])
            names = [c.strip().lower() for c in candidate]
            if len(names) > 1 and any(n in _VALUE_COLUMNS for n in names):
                header = names
            continue
        if line.strip():
            data_lines.append(line)

    def index_of(options: tuple[str, ...]) -> int | None:
        if header is None:
            return None
        for option in options:
            if option in header:
                return header.index(option)
        return None

    value_i = index_of(_VALUE_COLUMNS)
    family_i = index_of(_FAMILY_COLUMNS)
    date_i = index_of(_DATE_COLUMNS)
    iocs: list[IOC] = []
    for row in csv.reader(data_lines, skipinitialspace=True):
        cells = [c.strip() for c in row]
        if value_i is not None and value_i < len(cells):
            candidates = [cells[value_i]]
        else:
            candidates = cells
        ioc = next((i for i in (classify(c) for c in candidates) if i), None)
        if ioc is None:
            continue
        family = cells[family_i] if family_i is not None and family_i < len(cells) else ""
        first_seen = cells[date_i] if date_i is not None and date_i < len(cells) else ""
        iocs.append(IOC(ioc.kind, ioc.value, source, family.strip(), first_seen.strip()))
    return iocs


def _cache_dir() -> Path:
    base = os.environ.get("ARGUS_CACHE_DIR")
    root = Path(base) if base else Path.home() / ".cache" / "argus"
    return root / "threat-intel"


def _download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "argus-scan"})
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310 (fixed https URL)
        data = response.read(_MAX_DOWNLOAD + 1)
    if len(data) > _MAX_DOWNLOAD:
        raise ValueError("feed larger than the download limit")
    return data


def _feed_text(raw: bytes) -> str:
    if raw[:2] == b"PK":  # zip archive
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names = [n for n in archive.namelist() if n.lower().endswith((".csv", ".txt"))]
            if not names:
                return ""
            info = archive.getinfo(names[0])
            if info.file_size > _MAX_DOWNLOAD:
                raise ValueError("feed archive member too large")
            return archive.read(names[0]).decode("utf-8", errors="replace")
    return raw.decode("utf-8", errors="replace")


def load_feeds(notes: list[str]) -> list[IOC]:
    """Feed IOCs from cache or download. Problems become notes, never failures."""
    key = os.environ.get("ARGUS_ABUSECH_AUTH_KEY", "").strip()
    max_age = float(os.environ.get("ARGUS_IOC_MAX_AGE_HOURS", "24")) * 3600
    cache = _cache_dir()
    iocs: list[IOC] = []
    for name, (template, _home) in FEEDS.items():
        path = cache / f"{name.lower()}.bin"
        fresh = path.is_file() and time.time() - path.stat().st_mtime < max_age
        if not fresh and key and not network_disabled():
            try:
                raw = _download(template.format(key=key))
                cache.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            except (OSError, ValueError, urllib.error.URLError) as exc:
                notes.append(f"{name}: download failed ({exc}); using the cache if present")
        if not path.is_file():
            if not key:
                notes.append(f"{name}: skipped (set ARGUS_ABUSECH_AUTH_KEY; free at abuse.ch)")
            continue
        try:
            iocs.extend(parse_feed(_feed_text(path.read_bytes()), name))
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            notes.append(f"{name}: unreadable cache ({exc})")
    return iocs


def local_ioc_paths(target: Path) -> list[Path]:
    paths = [target / ".argus" / "iocs.txt"]
    if os.environ.get("ARGUS_IOC_FILE"):
        paths.append(Path(os.environ["ARGUS_IOC_FILE"]))
    return paths


def load_local_iocs(target: Path) -> list[IOC]:
    iocs: list[IOC] = []
    for path in local_ioc_paths(target):
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            value = line.split("#", 1)[0].strip()
            ioc = classify(value)
            if ioc:
                iocs.append(IOC(ioc.kind, ioc.value, f"local IOC list ({path.name})"))
    return iocs


# ── Matching ──────────────────────────────────────────────────────────────────


@dataclass
class _Index:
    urls: dict[str, IOC]
    domains: dict[str, IOC]
    ips: dict[str, IOC]
    hashes: dict[str, IOC]

    @classmethod
    def build(cls, iocs: list[IOC]) -> _Index:
        index = cls({}, {}, {}, {})
        for ioc in iocs:
            table = {"url": index.urls, "domain": index.domains, "ip": index.ips}.get(
                ioc.kind, index.hashes
            )
            table.setdefault(ioc.value, ioc)
        return index

    def __len__(self) -> int:
        return len(self.urls) + len(self.domains) + len(self.ips) + len(self.hashes)


def _domain_hit(host: str, domains: dict[str, IOC]) -> IOC | None:
    """The host or a parent domain is listed, unless it belongs to a big shared platform."""
    labels = host.lower().rstrip(".").split(".")
    for start in range(len(labels) - 1):
        candidate = ".".join(labels[start:])
        if candidate in _PLATFORM_DOMAINS:
            return None
        if candidate in domains:
            return domains[candidate]
    return None


def _iter_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        files.extend(Path(dirpath) / f for f in filenames)
    return files


def _finding(ioc: IOC, relative: str, line: int, where: str) -> Finding:
    family = (
        f" ({ioc.family})" if ioc.family and ioc.family.lower() not in {"none", "unknown"} else ""
    )
    seen = f", first seen {ioc.first_seen}" if ioc.first_seen else ""
    home = FEEDS.get(ioc.source, ("", ""))[1]
    return Finding(
        title=f"Known malicious {ioc.kind}{family}: {ioc.value}",
        severity=Severity.CRITICAL,
        scan_type=ScanType.MALWARE,
        tool=TOOL_NAME,
        file=relative,
        line=line,
        rule_id=f"threat-ioc-{ioc.kind}",
        confidence="high",
        description=f"{where} is listed by {ioc.source}{seen}.",
        fix_guidance=(
            "Remove the reference and find out how it got here (commit history, dependency, "
            "generated file). Treat machines and CI runners that ran this code as compromised "
            "and rotate the credentials they could reach."
        ),
        references=[home] if home else [],
    )


def match_target(root: Path, index: _Index) -> list[Finding]:
    base = root if root.is_dir() else root.parent
    # The IOC lists themselves contain every indicator: never match them.
    ioc_lists = {p.resolve() for p in local_ioc_paths(base) if p.is_file()}
    findings: list[Finding] = []
    for path in _iter_files(root):
        if path.is_symlink() or path.resolve() in ioc_lists:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        relative = path.relative_to(base).as_posix()
        try:
            with path.open("rb") as handle:
                head = handle.read(8192)
        except OSError:
            continue
        binary = b"\0" in head or path.suffix.lower() in _BINARY_SUFFIXES
        if binary:
            if index.hashes and size <= _MAX_HASHED_FILE:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                if digest in index.hashes:
                    findings.append(
                        _finding(index.hashes[digest], relative, 0, "This file's SHA-256")
                    )
            continue
        if size > _MAX_TEXT_FILE:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        seen: set[str] = set()
        for number, line in enumerate(text.splitlines(), start=1):
            for match in _URL_RE.finditer(line):
                url = _normalise_url(match.group(0))
                ioc = index.urls.get(url)
                try:
                    host = urlsplit(url).hostname or ""
                except ValueError:
                    host = ""
                ioc = ioc or (_domain_hit(host, index.domains) if host else None)
                ioc = ioc or index.ips.get(host)
                if ioc and ioc.value not in seen:
                    seen.add(ioc.value)
                    findings.append(_finding(ioc, relative, number, f"The URL {url}"))
            if index.domains:
                for match in _DOMAIN_RE.finditer(line):
                    ioc = _domain_hit(match.group(0), index.domains)
                    if ioc and ioc.value not in seen:
                        seen.add(ioc.value)
                        findings.append(
                            _finding(ioc, relative, number, f"The domain {match.group(0)}")
                        )
            if index.ips:
                for match in _IPV4_RE.finditer(line):
                    ioc = index.ips.get(match.group(0))
                    if ioc and ioc.value not in seen:
                        seen.add(ioc.value)
                        findings.append(_finding(ioc, relative, number, f"The IP {match.group(0)}"))
    return findings


def threat_intel_findings(target: str) -> tuple[list[Finding], dict[str, object], list[str]]:
    root = Path(target)
    notes: list[str] = []
    iocs = load_local_iocs(root if root.is_dir() else root.parent) + load_feeds(notes)
    index = _Index.build(iocs)
    metadata: dict[str, object] = {
        "iocs_loaded": len(index),
        "sources": sorted({i.source for i in iocs}),
    }
    if not len(index):
        return [], metadata, notes
    return match_target(root, index), metadata, notes


async def run_threat_scan(target: str) -> ScanResult:
    """`argus scan threats`: known IOCs (feeds + local list) matched against the repository."""
    result = ScanResult(tool=TOOL_NAME, scan_type=ScanType.MALWARE, target=target)
    findings, metadata, notes = await asyncio.to_thread(threat_intel_findings, target)
    result.findings.extend(findings)
    result.metadata.update(metadata)
    if notes:
        result.metadata["notes"] = notes
    return result
