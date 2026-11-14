"""Server-side template injection rules (#185): unsafe templates flagged, safe look-alikes quiet.

The cases live in fixtures/ssti_samples.json (the npm scanner's test uses the same cases) so
the samples don't trip Argus's own scan of this repository.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus_languages.scanner import scan_path

CASES = json.loads((Path(__file__).parent / "fixtures" / "ssti_samples.json").read_text())
SSTI_IDS = {
    "python-ssti-render-template-string",
    "python-ssti-template-from-input",
    "js-ssti-render-user-template",
    "php-ssti-template-from-input",
    "java-ssti-freemarker-string-template",
    "java-ssti-velocity-evaluate",
    "ruby-ssti-erb-from-input",
}


@pytest.mark.parametrize("case", CASES, ids=lambda c: f"{c['file']}: {c['code'][:50]}")
def test_ssti_rules(tmp_path: Path, case: dict[str, str | None]) -> None:
    (tmp_path / str(case["file"])).write_text(f"{case['code']}\n")
    found = sorted({f.rule_id for f in scan_path(tmp_path).findings} & SSTI_IDS)
    assert found == ([case["rule"]] if case["rule"] else [])
