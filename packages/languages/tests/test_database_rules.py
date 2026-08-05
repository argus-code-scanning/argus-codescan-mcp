"""Tests for database security static rules."""

from pathlib import Path

from argus_languages.scanner import scan_path


def test_db_connection_string(tmp_path: Path):
    f = tmp_path / "config.py"
    f.write_text('DATABASE_URL = "postgres://user:pass@localhost/db"\n')
    result = scan_path(f)
    rule_ids = {x.rule_id for x in result.findings}
    assert "db-connection-string" in rule_ids


def test_sql_migration_grant_all(tmp_path: Path):
    f = tmp_path / "001_init.sql"
    f.write_text("GRANT ALL PRIVILEGES ON *.* TO 'app'@'%';\n")
    result = scan_path(f)
    rule_ids = {x.rule_id for x in result.findings}
    assert "db-migration-grant-all" in rule_ids


def test_sqlalchemy_text_fstring(tmp_path: Path):
    f = tmp_path / "queries.py"
    f.write_text(
        'from sqlalchemy import text\nresult = text(f"SELECT * FROM users WHERE id={uid}")\n'
    )
    result = scan_path(f)
    rule_ids = {x.rule_id for x in result.findings}
    assert "db-sqlalchemy-text-fstring" in rule_ids
