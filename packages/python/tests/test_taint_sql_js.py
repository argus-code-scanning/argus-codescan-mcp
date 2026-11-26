"""SQL injection across lines in JavaScript / TypeScript, with tree-sitter (#183)."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.tools.taint_sql import taint_findings
from argus.tools.taint_sql_js import analyze_js_source, available

pytestmark = pytest.mark.skipif(not available(), reason="tree-sitter not installed")


def sinks(code: str, dialect: str = "javascript") -> list[tuple[int, str, str]]:
    return [(f.sink_line, f.sink, f.variable) for f in analyze_js_source(code, dialect)]


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (  # the issue's example: template literal
            "async function del(req, res) {\n"
            "  const id = req.query.id;\n"
            "  const sql = `DELETE FROM orders WHERE id = ${id}`;\n"
            "  await db.query(sql);\n"
            "}",
            [(4, "query", "sql")],
        ),
        (  # destructuring + concatenation + +=
            "app.get('/u', async (req, res) => {\n"
            "  const { name } = req.query;\n"
            "  let q = 'SELECT * FROM users WHERE 1=1';\n"
            '  q += " AND name = \'" + name + "\'";\n'
            "  const rows = await pool.query(q);\n"
            "});",
            [(5, "query", "q")],
        ),
        (  # knex.raw and Prisma unsafe
            "async function f(req) {\n"
            "  const col = req.body.sort;\n"
            "  const order = `ORDER BY ${col}`;\n"
            "  await knex.raw(order);\n"
            "  await prisma.$queryRawUnsafe(order);\n"
            "}",
            [(4, "raw", "order"), (5, "$queryRawUnsafe", "order")],
        ),
        (  # tainted on one branch is still tainted after the if
            "function f(req) {\n"
            "  let sql = 'SELECT 1';\n"
            "  if (req.query.all) { sql = 'SELECT * FROM t WHERE x = ' + req.query.x; }\n"
            "  return connection.query(sql);\n"
            "}",
            [(4, "query", "sql")],
        ),
        (  # better-sqlite3 style on a db handle
            "function f(req) {\n"
            "  const s = `SELECT * FROM t WHERE name = '${req.params.name}'`;\n"
            "  return db.prepare(s).all();\n"
            "}",
            [(3, "prepare", "s")],
        ),
    ],
)
def test_flows_are_found(code: str, expected: list[tuple[int, str, str]]) -> None:
    assert sinks(code) == expected


@pytest.mark.parametrize(
    "code",
    [
        # parameterized: SQL text is constant
        "async function f(req) {\n  const id = req.query.id;\n  await db.query('SELECT * FROM t WHERE id = $1', [id]);\n}",
        # number cast clears the taint
        "async function f(req) {\n  const id = parseInt(req.query.id, 10);\n  const sql = `SELECT * FROM t WHERE id = ${id}`;\n  await db.query(sql);\n}",
        "async function f(req) {\n  const id = Number(req.params.id);\n  const sql = 'SELECT * FROM t WHERE id = ' + id;\n  await db.query(sql);\n}",
        # allowlist with early exit
        "async function f(req, res) {\n  const col = req.query.sort;\n  if (!ALLOWED.includes(col)) return res.status(400).end();\n  const sql = `SELECT * FROM t ORDER BY ${col}`;\n  await db.query(sql);\n}",
        # reassigned from a constant
        "async function f(req) {\n  let sql = 'SELECT ' + req.query.c;\n  sql = 'SELECT 1';\n  await db.query(sql);\n}",
        # same line: the line rules' job, not reported twice
        "async function f(req) {\n  await db.query(`SELECT * FROM t WHERE id = ${req.query.id}`);\n}",
        # child_process.exec / RegExp.exec are not SQL
        "function f(req) {\n  const cmd = 'ls ' + req.query.dir;\n  child_process.exec(cmd);\n  const m = re.exec(cmd);\n}",
        # input from another function's scope is not followed
        "const id = req.query.id;\nfunction f() {\n  const sql = 'SELECT ' + id;\n  return db.query(sql);\n}",
    ],
)
def test_safe_code_is_not_reported(code: str) -> None:
    assert sinks(code) == []


def test_typescript_and_tsx() -> None:
    ts = (
        "export async function handler(req: Request, res: Response): Promise<void> {\n"
        "  const id = req.query.id as string;\n"
        "  const sql: string = `SELECT * FROM t WHERE id = '${id}'`;\n"
        "  await this.dataSource.query(sql);\n"
        "}"
    )
    assert sinks(ts, "typescript") == [(4, "query", "sql")]
    tsx = "export function C() { return <div/>; }\n" + ts
    assert sinks(tsx, "tsx") == [(5, "query", "sql")]


def test_through_the_scan(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "orders.js").write_text(
        "async function del(req) {\n  const id = req.query.id;\n  const sql = `DELETE FROM o WHERE id = ${id}`;\n  await db.query(sql);\n}\n"
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "orders.test.js").write_text((tmp_path / "src" / "orders.js").read_text())
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "bundle.js").write_text((tmp_path / "src" / "orders.js").read_text())
    findings, meta = taint_findings(str(tmp_path))
    assert [(f.file, f.line, f.rule_id) for f in findings] == [
        ("src/orders.js", 4, "js-sql-injection-taint")
    ]
    assert "req.query.id (line 2)" in findings[0].title and meta["js_ts_files"] == 1


def test_nestjs_decorated_parameters_are_input() -> None:
    code = (
        "@Controller('orders')\n"
        "export class OrdersController {\n"
        "  @Get()\n"
        "  async list(@Query('sort') sort: string, @Body() dto: CreateDto, limit: number) {\n"
        "    const sql = `SELECT * FROM orders ORDER BY ${sort}`;\n"
        "    const safe = `SELECT * FROM orders LIMIT ${limit}`;\n"
        "    await this.dataSource.query(sql);\n"
        "    await this.dataSource.query(safe);\n"
        "  }\n"
        "}"
    )
    found = analyze_js_source(code, "typescript")
    assert [(f.sink_line, f.variable) for f in found] == [(7, "sql")]
    assert found[0].origin.what == "@Query('sort') sort" and found[0].origin.line == 4
