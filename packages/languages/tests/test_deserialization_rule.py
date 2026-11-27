"""Shared `deserialization` rule: yaml.load with a safe loader is plain data."""

from __future__ import annotations

import pytest

from argus_languages.rules_loader import load_rules_from_files

RULE = next(
    r
    for r in load_rules_from_files(("common.yaml",))
    if r.id == "deserialization" and r.languages and "python" in r.languages
)


@pytest.mark.parametrize(
    "text",
    [
        "data = yaml.load(text)",
        "data = yaml.load(text, Loader=yaml.Loader)",
        "data = yaml.load(text, Loader=yaml.UnsafeLoader)",
        "obj = pickle.loads(blob)",
    ],
)
def test_flags_unsafe_loading(text: str) -> None:
    assert RULE.pattern.search(text)


@pytest.mark.parametrize(
    "text",
    [
        "data = yaml.load(text, Loader=yaml.SafeLoader)",
        "data = yaml.load(text, Loader=yaml.CSafeLoader)",
        "data = yaml.load(text, Loader=SafeLoader)",
        "data = yaml.load(stream, Loader=yaml.BaseLoader)",
        "data = yaml.safe_load(text)",
    ],
)
def test_safe_loaders_are_not_flagged(text: str) -> None:
    assert not RULE.pattern.search(text)
