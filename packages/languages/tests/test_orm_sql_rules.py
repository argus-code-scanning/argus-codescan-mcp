"""ORM and query-builder SQL injection rules (#182): TypeORM, Knex, Prisma, Sequelize.

The cases live in fixtures/orm_sql_samples.json (the npm scanner's test uses the same cases) so
the samples don't trip Argus's own scan of this repository.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus_languages.scanner import scan_path

CASES = json.loads((Path(__file__).parent / "fixtures" / "orm_sql_samples.json").read_text())
ORM_IDS = {
    "js-typeorm-sql-interpolation",
    "js-knex-raw-interpolation",
    "js-prisma-raw-unsafe",
    "js-sequelize-literal-interpolation",
    "js-orm-order-by-input",
}


@pytest.mark.parametrize("case", CASES, ids=lambda c: f"{c['file']}: {c['code'][:50]}")
def test_orm_sql_rules(tmp_path: Path, case: dict[str, str | None]) -> None:
    (tmp_path / str(case["file"])).write_text(f"{case['code']}\n")
    found = sorted({f.rule_id for f in scan_path(tmp_path).findings} & ORM_IDS)
    assert found == ([case["rule"]] if case["rule"] else [])


def test_order_by_input_is_low_confidence(tmp_path: Path) -> None:
    (tmp_path / "repo.ts").write_text("qb.orderBy(req.query" + ".sort, 'ASC');\n")
    [finding] = [f for f in scan_path(tmp_path).findings if f.rule_id == "js-orm-order-by-input"]
    assert finding.confidence == "low"
