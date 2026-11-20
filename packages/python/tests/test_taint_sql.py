"""SQL injection across lines: intra-function taint tracking (#183)."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.models import Severity
from argus.tools.taint_sql import analyze_source, run_taint_sql_check, taint_findings

VULNERABLE = {
    "flask concat": (
        "@app.route('/users')\n"
        "def users():\n"
        "    name = request.args['name']\n"
        '    query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
        "    cursor.execute(query)\n",
        ("request.args", 3, "execute", 5),
    ),
    "django f-string + raw": (
        "def search(request):\n"
        "    term = request.GET.get('q')\n"
        "    sql = f\"SELECT * FROM items WHERE title LIKE '%{term}%'\"\n"
        "    return Item.objects.raw(sql)\n",
        ("request.GET", 2, "raw", 4),
    ),
    "fastapi param + format + text": (
        "@router.get('/orders')\n"
        "async def orders(status: str, db: Session = Depends(get_db)):\n"
        "    q = \"SELECT * FROM orders WHERE status = '{}'\".format(status)\n"
        "    return db.execute(text(q)).all()\n",
        ("route parameter 'status'", 2, "text", 4),
    ),
    "percent + join + read_sql": (
        "@app.post('/report')\n"
        "def report():\n"
        "    cols = request.json['columns']\n"
        "    select = ', '.join(cols)\n"
        "    stmt = 'SELECT %s FROM sales' % select\n"
        "    rows = pd.read_sql(stmt, engine)\n",
        ("request.json", 3, "read_sql", 6),
    ),
    "one branch tainted": (
        "@app.route('/x')\n"
        "def x():\n"
        "    order = request.args.get('order', 'id')\n"
        "    if order:\n"
        "        sql = 'SELECT * FROM t ORDER BY ' + order\n"
        "    else:\n"
        "        sql = 'SELECT * FROM t'\n"
        "    cur.execute(sql)\n",
        ("request.args", 3, "execute", 8),
    ),
    "sink inside if body": (
        "@app.route('/y')\n"
        "def y():\n"
        "    q = request.args['q']\n"
        "    if q:\n"
        "        sql = 'SELECT * FROM t WHERE a = ' + q\n"
        "        cur.execute(sql)\n",
        ("request.args", 3, "execute", 6),
    ),
    "loop accumulation": (
        "@app.route('/z')\n"
        "def z():\n"
        "    sql = 'SELECT * FROM t WHERE 1=1'\n"
        "    for key in request.args:\n"
        "        sql += ' AND ' + key + ' = 1'\n"
        "    cur.execute(sql)\n",
        ("request.args", 4, "execute", 6),
    ),
    "try / except": (
        "@app.route('/w')\n"
        "def w():\n"
        "    try:\n"
        "        tbl = request.args['table']\n"
        "    except KeyError:\n"
        "        tbl = 'users'\n"
        "    sql = f'SELECT * FROM {tbl}'\n"
        "    cur.execute(sql)\n",
        ("request.args", 4, "execute", 8),
    ),
}

SAFE = {
    "parameterized": (
        "@app.route('/u')\ndef u():\n    name = request.args['name']\n"
        "    query = 'SELECT * FROM users WHERE name = %s'\n    cursor.execute(query, (name,))\n"
    ),
    "int cast": (
        "@app.route('/u')\ndef u():\n    uid = int(request.args['id'])\n"
        "    q = f'SELECT * FROM users WHERE id = {uid}'\n    cursor.execute(q)\n"
    ),
    "allowlist guard": (
        "@app.route('/s')\ndef s():\n    col = request.args.get('col')\n"
        "    if col not in ALLOWED_COLUMNS:\n        abort(400)\n"
        "    q = f'SELECT * FROM t ORDER BY {col}'\n    cursor.execute(q)\n"
    ),
    "reassigned safe": (
        "@app.route('/r')\ndef r():\n    q = request.args['q']\n    q = 'SELECT 1'\n    cursor.execute(q)\n"
    ),
    "both branches safe": (
        "@app.route('/b')\ndef b():\n    flag = request.args.get('f')\n    if flag:\n"
        "        sql = 'SELECT 1'\n    else:\n        sql = 'SELECT 2'\n    cur.execute(sql)\n"
    ),
    "fastapi typed param and dependency": (
        "@router.get('/item/{item_id}')\ndef item(item_id: int, db=Depends(get_db)):\n"
        "    q = f'SELECT * FROM items WHERE id = {item_id}'\n    db.execute(text(q))\n"
    ),
    "not a request handler": (
        'def build(name):\n    q = "SELECT * FROM t WHERE n = \'" + name + "\'"\n    cursor.execute(q)\n'
    ),
    "same line (line rules cover it)": (
        "@app.route('/s')\ndef s():\n"
        "    cursor.execute(\"SELECT * FROM t WHERE n = '\" + request.args['n'] + \"'\")\n"
    ),
    "unparsable": "def broken(:\n",
}


@pytest.mark.parametrize(("source", "expected"), VULNERABLE.values(), ids=list(VULNERABLE))
def test_flows_across_lines_are_found(source: str, expected: tuple[str, int, str, int]) -> None:
    hits = analyze_source(source)
    assert [(h.origin.what, h.origin.line, h.sink, h.sink_line) for h in hits] == [expected]


@pytest.mark.parametrize("source", SAFE.values(), ids=list(SAFE))
def test_safe_code_is_quiet(source: str) -> None:
    assert analyze_source(source) == []


def test_findings_skip_tests_and_report_the_path(tmp_path: Path) -> None:
    source = VULNERABLE["flask concat"][0]
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "views.py").write_text(source)
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_views.py").write_text(source)
    findings, meta = taint_findings(str(tmp_path))
    assert [(f.file, f.line, f.severity, f.rule_id, f.cwe) for f in findings] == [
        ("app/views.py", 5, Severity.HIGH, "python-sql-injection-taint", "CWE-89")
    ]
    assert (
        "request.args (line 3)" in findings[0].title
        and "execute(query) (line 5)" in findings[0].title
    )
    assert meta["python_files"] == 1


@pytest.mark.asyncio
async def test_part_of_the_sast_scan(tmp_path: Path) -> None:
    from argus.tools.sast import run_all_sast

    (tmp_path / "views.py").write_text(VULNERABLE["django f-string + raw"][0])
    direct = await run_taint_sql_check(str(tmp_path))
    assert [f.rule_id for f in direct.findings] == ["python-sql-injection-taint"]
    results = await run_all_sast(str(tmp_path))
    assert any(r.tool == "argus-taint-sql" and r.findings for r in results)
