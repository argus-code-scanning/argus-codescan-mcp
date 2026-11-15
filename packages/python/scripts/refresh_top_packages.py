"""Refresh the bundled popular-package lists used by the typosquat check (#142).

    python packages/python/scripts/refresh_top_packages.py

Sources (both public, no account needed):
- PyPI: hugovk/top-pypi-packages, downloads over the last 30 days
- npm:  wooorm/npm-high-impact (`lib/top.js`: top packages by downloads and dependents)

Only names are stored. The npm package is downloaded as a tarball and read as text; nothing
from it is executed.
"""

from __future__ import annotations

import io
import json
import re
import tarfile
import urllib.request
from pathlib import Path

# Full lists: every name here counts as an established package (never reported); the most
# popular ones are also the typosquat targets (see argus/tools/typosquats.py).
LIMIT = 20000
DATA = Path(__file__).resolve().parents[1] / "src" / "argus" / "data"
PYPI_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages-30-days.min.json"
NPM_PACKAGE = "npm-high-impact"


def _get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "argus-scan refresh script"})
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 (fixed https URLs)
        return response.read()


def pypi_names() -> tuple[list[str], str]:
    data = json.loads(_get(PYPI_URL))
    names = [row["project"].lower() for row in data["rows"]][:LIMIT]
    return names, f"hugovk/top-pypi-packages, {data.get('last_update', '?')}"


def npm_names() -> tuple[list[str], str]:
    meta = json.loads(_get(f"https://registry.npmjs.org/{NPM_PACKAGE}/latest"))
    archive = tarfile.open(fileobj=io.BytesIO(_get(meta["dist"]["tarball"])), mode="r:gz")
    member = archive.extractfile("package/lib/top.js")
    if member is None:
        raise SystemExit("npm-high-impact layout changed: package/lib/top.js missing")
    text = member.read().decode("utf-8")
    names = re.findall(r"^\s*'([^']+)',?$", text, re.MULTILINE)[:LIMIT]
    return names, f"{NPM_PACKAGE} {meta['version']}"


def main() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    for filename, (names, source) in (("top_pypi.txt", pypi_names()), ("top_npm.txt", npm_names())):
        header = f"# Top {len(names)} packages, source: {source}. Refresh: scripts/refresh_top_packages.py\n"
        (DATA / filename).write_text(header + "\n".join(names) + "\n", encoding="utf-8")
        print(f"{filename}: {len(names)} names ({source})")


if __name__ == "__main__":
    main()
