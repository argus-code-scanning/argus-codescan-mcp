"""Prototype pollution in JavaScript / TypeScript (#188)."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages import scan_directory
from argus_languages.rules_loader import RULE_FILES, load_rules_from_files

IDS = {r.id for r in load_rules_from_files(("prototype-pollution.yaml",))}


def findings(tmp_path: Path, code: str, name: str = "app.js") -> dict[str, str]:
    (tmp_path / name).write_text(code)
    return {f.rule_id: f.confidence for f in scan_directory(tmp_path).findings if f.rule_id in IDS}


def test_pack_registered_with_guidance() -> None:
    assert "prototype-pollution.yaml" in RULE_FILES
    rules = load_rules_from_files(("prototype-pollution.yaml",))
    assert all(r.fix_guidance and r.guarded_by is not None for r in rules)


@pytest.mark.parametrize(
    ("code", "rule"),
    [
        ("_.merge(config, req.body);", "js-prototype-pollution-deep-merge"),
        ("_.defaultsDeep(settings, req.query);", "js-prototype-pollution-deep-merge"),
        ("_.set(user, req.body.path, req.body.value);", "js-prototype-pollution-deep-merge"),
        ("$.extend(true, options, req.body);", "js-prototype-pollution-deep-merge"),
        (
            "const merged = deepmerge(defaults, JSON.parse(req.body.json));",
            "js-prototype-pollution-deep-merge",
        ),
        ("merge(target, ctx.request.body);", "js-prototype-pollution-deep-merge"),
        ("obj[req.query.key] = req.query.value;", "js-prototype-pollution-computed-key"),
        ("store[req.body.section][req.body.key] = 1;", "js-prototype-pollution-computed-key"),
        ("tree[a][b] = req.body.value;", "js-prototype-pollution-computed-key"),
        ("Object.assign(config, req.body);", "js-prototype-pollution-object-assign"),
    ],
)
def test_flags(tmp_path: Path, code: str, rule: str) -> None:
    assert rule in findings(tmp_path, code + "\n")


@pytest.mark.parametrize(
    "code",
    [
        "_.merge(config, defaults);",
        "const body = schema.parse(req.body);\n_.merge(config, body);",
        "const { name, email } = req.body;",
        "Object.assign({}, req.body);",
        "Object.assign(Object.create(null), req.body);",
        "const m = new Map(); m.set(req.query.key, 1);",
        "if (obj[req.query.key] === undefined) {}",
        "matrix[i][j] = 0;",
        "const v = cache[req.query.key];",
    ],
)
def test_safe(tmp_path: Path, code: str) -> None:
    assert findings(tmp_path, code + "\n") == {}


def test_guard_in_the_file_lowers_confidence(tmp_path: Path) -> None:
    guarded, plain = tmp_path / "guarded", tmp_path / "plain"
    guarded.mkdir()
    plain.mkdir()
    code = (
        "function safeKey(k) { if (k === '__proto__' || k === 'constructor') throw new Error(); }\n"
        "_.merge(config, req.body);\n"
    )
    assert findings(guarded, code) == {"js-prototype-pollution-deep-merge": "low"}
    assert findings(plain, "_.merge(config, req.body);\n") == {
        "js-prototype-pollution-deep-merge": "medium"
    }


def test_typescript(tmp_path: Path) -> None:
    assert "js-prototype-pollution-deep-merge" in findings(
        tmp_path, "_.merge(cfg, req.body as Config);\n", "app.ts"
    )
