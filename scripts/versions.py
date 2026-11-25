#!/usr/bin/env python3
"""Release versions for every Argus package, kept in one place (#11).

    python scripts/versions.py show
    python scripts/versions.py check            # CI: files agree, pin matches, README table current
    python scripts/versions.py bump --scan 0.11.0 --languages 0.9.0 --npm 0.13.0 [--vscode 0.2.0]
    python scripts/versions.py sync             # pin + README table from the current versions

Packages keep their own version numbers; this script keeps every file that holds one in
sync, pins argus-scan to the argus-languages it was tested with, and rewrites the
compatibility table in the README. Standard library only.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
TABLE_START = "<!-- versions:start -->"
TABLE_END = "<!-- versions:end -->"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-.]?(?:a|b|rc|dev|post)\.?\d+)?$")


@dataclass(frozen=True)
class Location:
    path: str
    pattern: str  # regex with one group around the version


PACKAGES: dict[str, tuple[str, str, list[Location]]] = {
    # key: (published name, where, files)
    "languages": (
        "argus-languages",
        "PyPI",
        [
            Location("packages/languages/pyproject.toml", r'(?m)^version = "([^"]+)"'),
            Location(
                "packages/languages/src/argus_languages/__init__.py",
                r'(?m)^__version__ = "([^"]+)"',
            ),
        ],
    ),
    "scan": (
        "argus-scan",
        "PyPI",
        [
            Location("packages/python/pyproject.toml", r'(?m)^version = "([^"]+)"'),
            Location("packages/python/src/argus/__init__.py", r'(?m)^__version__ = "([^"]+)"'),
        ],
    ),
    "npm": (
        "argus-codescan",
        "npm",
        [
            Location("packages/npm/package.json", r'(?m)^  "version": "([^"]+)"'),
            Location("packages/npm/package-lock.json", r'(?m)^  "version": "([^"]+)"'),
            # The root package entry in the lockfile ("packages": { "": { ... } }).
            Location(
                "packages/npm/package-lock.json",
                r'"": \{\s*"name": "argus-codescan",\s*"version": "([^"]+)"',
            ),
        ],
    ),
    "vscode": (
        "argus-scan (VS Code)",
        "Marketplace",
        [
            Location("extensions/vscode/package.json", r'(?m)^  "version": "([^"]+)"'),
            Location("extensions/vscode/package-lock.json", r'(?m)^  "version": "([^"]+)"'),
            Location(
                "extensions/vscode/package-lock.json",
                r'"": \{\s*"name": "argus-scan",\s*"version": "([^"]+)"',
            ),
        ],
    ),
}
PIN = Location("packages/python/pyproject.toml", r'"argus-languages>=([^"]+)"')


def _read(loc: Location, root: Path) -> str | None:
    text = (root / loc.path).read_text(encoding="utf-8")
    m = re.search(loc.pattern, text)
    return m.group(1) if m else None


def _write(loc: Location, version: str, root: Path) -> None:
    path = root / loc.path
    text = path.read_text(encoding="utf-8")
    m = re.search(loc.pattern, text)
    if not m:
        raise SystemExit(f"{loc.path}: version not found ({loc.pattern})")
    path.write_text(text[: m.start(1)] + version + text[m.end(1) :], encoding="utf-8")


def current(root: Path = ROOT) -> dict[str, str]:
    return {key: _read(locs[0], root) or "?" for key, (_, _, locs) in PACKAGES.items()}


def table(versions: dict[str, str], pin: str) -> str:
    rows = [
        "| Package | Version | Install |",
        "|---|---|---|",
        f"| `argus-scan` (CLI + MCP) | {versions['scan']} | `pip install argus-scan=={versions['scan']}` "
        f"(needs `argus-languages>={pin}`) |",
        f"| `argus-languages` (built-in rules) | {versions['languages']} | "
        f"`pip install argus-languages=={versions['languages']}` |",
        f"| `argus-codescan` (npm) | {versions['npm']} | `npx argus-codescan@{versions['npm']}` |",
        f"| VS Code extension | {versions['vscode']} | Marketplace: `arestechub.argus-scan` |",
    ]
    return "\n".join(rows)


def _readme_table(root: Path) -> str | None:
    text = (root / "README.md").read_text(encoding="utf-8")
    m = re.search(re.escape(TABLE_START) + r"\n(.*?)\n" + re.escape(TABLE_END), text, re.S)
    return m.group(1) if m else None


def _write_readme_table(root: Path, body: str) -> None:
    path = root / "README.md"
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(re.escape(TABLE_START) + r".*?" + re.escape(TABLE_END), re.S)
    if not pattern.search(text):
        raise SystemExit(f"README.md: {TABLE_START} ... {TABLE_END} markers not found")
    path.write_text(
        pattern.sub(lambda _: f"{TABLE_START}\n{body}\n{TABLE_END}", text), encoding="utf-8"
    )


def problems(root: Path = ROOT) -> list[str]:
    out: list[str] = []
    for key, (name, _, locs) in PACKAGES.items():
        found = {
            loc.path + ("" if i == 0 else f" #{i}"): _read(loc, root) for i, loc in enumerate(locs)
        }
        values = set(found.values())
        if None in values:
            missing = [p for p, v in found.items() if v is None]
            out.append(f"{name}: no version found in {', '.join(missing)}")
        elif len(values) > 1:
            out.append(
                f"{name}: files disagree: " + ", ".join(f"{p}={v}" for p, v in found.items())
            )
    versions = current(root)
    pin = _read(PIN, root)
    if pin != versions["languages"]:
        out.append(
            f"argus-scan requires argus-languages>={pin} but argus-languages is {versions['languages']}; "
            "pin the version it was tested with (versions.py bump does this)"
        )
    expected = table(versions, pin or "?")
    if _readme_table(root) != expected:
        out.append(
            "README.md version table is out of date: run python scripts/versions.py bump (or show --table)"
        )
    return out


def bump(root: Path, new: dict[str, str]) -> None:
    for key, version in new.items():
        if not VERSION_RE.match(version):
            raise SystemExit(f"--{key}: {version!r} is not a version like 1.2.3")
        for loc in PACKAGES[key][2]:
            _write(loc, version, root)
    sync(root)


def sync(root: Path) -> None:
    """Pin argus-scan to the current argus-languages and rewrite the README table."""
    versions = current(root)
    _write(PIN, versions["languages"], root)
    _write_readme_table(root, table(versions, versions["languages"]))


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    show = sub.add_parser("show", help="Print every package version")
    show.add_argument("--table", action="store_true", help="Print the README table")
    sub.add_parser("check", help="Exit 1 when versions are out of sync")
    sub.add_parser("sync", help="Update the pin and README table from the current versions")
    b = sub.add_parser("bump", help="Set new versions and update every file")
    for key in PACKAGES:
        b.add_argument(f"--{key}", metavar="X.Y.Z")
    args = parser.parse_args(argv)

    if args.cmd == "show":
        versions = current(root)
        if args.table:
            print(table(versions, _read(PIN, root) or "?"))
        else:
            for key, (name, where, _) in PACKAGES.items():
                print(f"{name:<22} {versions[key]:<10} {where}")
            print(f"{'argus-scan pins':<22} argus-languages>={_read(PIN, root)}")
        return 0
    if args.cmd == "check":
        found = problems(root)
        for p in found:
            print(f"✗ {p}", file=sys.stderr)
        if not found:
            print(
                "✓ versions in sync: "
                + ", ".join(f"{PACKAGES[k][0]} {v}" for k, v in current(root).items())
            )
        return 1 if found else 0
    if args.cmd == "sync":
        sync(root)
        print("Synced the argus-languages pin and the README table.")
        return 0
    new = {k: v for k in PACKAGES if (v := getattr(args, k))}
    if not new:
        parser.error("bump needs at least one of " + ", ".join(f"--{k}" for k in PACKAGES))
    bump(root, new)
    print("Updated:", ", ".join(f"{PACKAGES[k][0]} {v}" for k, v in new.items()))
    print("Next: commit, open the release PR, then publish (see README → Versions).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
