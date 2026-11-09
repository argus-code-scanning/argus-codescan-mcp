"""SQL built from strings (issue #108): statement shapes with a variable in a value position."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages import scan_directory

SQL_RULES = {
    "python-sql-string-build",
    "js-sql-string-build",
    "java-sql-string-build",
    "kotlin-sql-string-template",
    "go-sql-string-build",
    "sql-concat",
}


def _findings(tmp_path: Path, filename: str, code: str) -> set[str]:
    path = tmp_path / filename
    path.write_text(code)
    return {f.rule_id for f in scan_directory(tmp_path).findings if f.rule_id in SQL_RULES}


@pytest.mark.parametrize(
    ("filename", "code", "rule"),
    [
        # Python
        (
            "db.py",
            'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            "python-sql-string-build",
        ),
        (
            "db.py",
            "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
            "python-sql-string-build",
        ),
        (
            "db.py",
            "cursor.execute(f'UPDATE users SET name = \"{name}\" WHERE id = 1')",
            "python-sql-string-build",
        ),
        (
            "db.py",
            'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
            "python-sql-string-build",
        ),
        (
            "db.py",
            'cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))',
            "python-sql-string-build",
        ),
        (
            "db.py",
            'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
            "python-sql-string-build",
        ),
        (
            "db.py",
            'cursor.execute("DELETE FROM sessions WHERE token = \'" + token + "\'")',
            "python-sql-string-build",
        ),
        # JavaScript / TypeScript
        ("db.js", "db.query(`SELECT * FROM users WHERE id = ${id}`);", "js-sql-string-build"),
        ("db.ts", "db.query(`SELECT * FROM users WHERE name = '${name}'`);", "js-sql-string-build"),
        (
            "db.js",
            'db.query("SELECT * FROM users WHERE id = " + req.params.id);',
            "js-sql-string-build",
        ),
        (
            "db.ts",
            'db.query("DELETE FROM sessions WHERE token = \'" + token + "\'");',
            "js-sql-string-build",
        ),
        # Java
        (
            "App.java",
            'Statement.execute("SELECT * FROM users WHERE id=" + userId);',
            "java-sql-string-build",
        ),
        (
            "App.java",
            'String sql = "SELECT * FROM users WHERE name = \'" + name + "\'";',
            "java-sql-string-build",
        ),
        (
            "App.java",
            'String q = String.format("SELECT * FROM users WHERE id = %s", id);',
            "java-sql-string-build",
        ),
        (
            "App.java",
            'String q = "SELECT * FROM users WHERE id = %d".formatted(id);',
            "java-sql-string-build",
        ),
        # Kotlin
        (
            "App.kt",
            "db.execSQL(\"DELETE FROM sessions WHERE token = '$token'\")",
            "kotlin-sql-string-template",
        ),
        ("App.kt", 'val q = "SELECT * FROM users WHERE id = ${id}"', "kotlin-sql-string-template"),
        ("App.kt", 'val q = "SELECT * FROM users WHERE id = " + id', "java-sql-string-build"),
        # Go
        (
            "db.go",
            'db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))',
            "go-sql-string-build",
        ),
        (
            "db.go",
            'db.Query("SELECT * FROM users WHERE name = \'" + name + "\'")',
            "go-sql-string-build",
        ),
        ("db.go", "db.Exec(fmt.Sprintf(`DELETE FROM t WHERE id = %v`, id))", "go-sql-string-build"),
        # Ruby, C#, Scala keep the generic rule id
        ("user.rb", 'User.find_by_sql("SELECT * FROM users WHERE id = #{id}")', "sql-concat"),
        ("Repo.cs", 'var q = $"SELECT * FROM users WHERE id = {id}";', "sql-concat"),
        ("Repo.cs", 'var q = "SELECT * FROM users WHERE id = " + id;', "sql-concat"),
        ("Repo.scala", 'val q = s"SELECT * FROM users WHERE id = $id"', "sql-concat"),
    ],
)
def test_sql_built_from_variables_is_flagged(
    tmp_path: Path, filename: str, code: str, rule: str
) -> None:
    assert rule in _findings(tmp_path, filename, f"{code}\n")


@pytest.mark.parametrize(
    ("filename", "code"),
    [
        # Parameterised queries
        ("db.py", 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'),
        ("db.py", 'session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})'),
        ("db.js", 'db.query("SELECT * FROM users WHERE id = $1", [id]);'),
        ("db.js", 'db.query("SELECT * FROM users WHERE id = ?", [id]);'),
        ("db.ts", "const rows = await sql`SELECT * FROM users WHERE id = ${id}`;"),
        ("App.java", 'conn.prepareStatement("SELECT * FROM users WHERE id = ?");'),
        ("App.java", 'client.preparedQuery("SELECT * FROM users WHERE id = $1");'),
        ("App.kt", 'db.rawQuery("SELECT * FROM users WHERE id = ?", arrayOf(id))'),
        ("App.kt", 'val q = "SELECT * FROM users WHERE id = $1"'),
        ("db.go", 'db.Query("SELECT * FROM users WHERE id = $1", id)'),
        ("db.go", 'db.Query("SELECT * FROM users WHERE id = ?", id)'),
        ("user.rb", 'User.where("id = ?", id)'),
        ("Repo.cs", 'var q = "SELECT * FROM users WHERE id = @id";'),
        # Table or column names built from variables are not value positions
        ("db.py", 'cursor.execute(f"SELECT * FROM {table} WHERE id = %s", (user_id,))'),
        ("db.go", 'q := fmt.Sprintf("SELECT * FROM %s WHERE id = $1", table)'),
        # Words that happen to be SQL keywords
        ("ui.py", 'print("Select scan target")'),
        ("ui.ts", "const label = `Select ${count} files from ${folder}`;"),
        ("App.java", 'log.info("Select from the list " + name);'),
    ],
)
def test_safe_code_is_not_flagged(tmp_path: Path, filename: str, code: str) -> None:
    assert _findings(tmp_path, filename, f"{code}\n") == set()


@pytest.mark.parametrize(
    ("filename", "code"),
    [
        # The five false positives listed in issue #108
        ("ansible.py", "    selected = tools or ALL_TOOLS"),
        ("code.py", "    result.metadata.update(native.metadata)"),
        ("webview.ts", "  user-select: none;"),
        ("extension.ts", '  { placeHolder: "Select scan target" }'),
        ("review-cli.ts", "// Deleted files and symlinks are skipped."),
    ],
)
def test_lines_from_issue_108_are_not_flagged(tmp_path: Path, filename: str, code: str) -> None:
    assert _findings(tmp_path, filename, f"{code}\n") == set()


def test_rules_only_apply_to_their_own_language(tmp_path: Path) -> None:
    cases = {
        "py_rule_in_ruby": (
            "x.rb",
            'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n',
        ),
        "java_rule_in_go": (
            "x.go",
            'String q = "SELECT * FROM users WHERE id = %s".formatted(id);\n',
        ),
        "text_file": ("notes.txt", 'db.query("SELECT * FROM users WHERE id = " + id);\n'),
    }
    for name, (filename, code) in cases.items():
        folder = tmp_path / name
        folder.mkdir()
        found = _findings(folder, filename, code)
        assert "python-sql-string-build" not in found, name
        assert "java-sql-string-build" not in found, name
        if filename.endswith(".txt"):
            assert found == set(), name
