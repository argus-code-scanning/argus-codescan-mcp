"""Tests for database security static rules."""

from pathlib import Path

import pytest

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


# ── db-redis-keys-prod: Redis KEYS only, not every .keys() call ─────────────


@pytest.mark.parametrize(
    ("filename", "line"),
    [
        ("cache.py", 'for k in r.keys("session:*"):'),
        ("cache.py", "keys = redis_client.keys(pattern)"),
        ("cache.py", "keys = await self.redis.keys(prefix + '*')"),
        ("cache.py", 'client.execute_command("KEYS", "*")'),
        ("cache.js", "const keys = await client.keys('user:*');"),
        ("cache.ts", "const all = await redisClient.keys(`${prefix}*`);"),
        ("cache.js", "await client.sendCommand(['KEYS', '*']);"),
        ("Cache.java", 'Set<String> keys = jedis.keys("order:*");'),
        ("Cache.java", 'Set<String> keys = redisTemplate.keys("order:*");'),
        ("cache.go", 'keys, err := rdb.Keys(ctx, "user:*").Result()'),
        ("cache.rb", 'redis.keys("job:*").each { |k| redis.del(k) }'),
        ("cache.php", "$keys = $redis->keys('cache:*');"),
        ("cache.php", "$keys = Redis::keys('cache:*');"),
    ],
)
def test_redis_keys_flagged(tmp_path: Path, filename: str, line: str):
    f = tmp_path / filename
    f.write_text(line + "\n")
    rule_ids = {x.rule_id for x in scan_path(f).findings}
    assert "db-redis-keys-prod" in rule_ids


@pytest.mark.parametrize(
    ("filename", "line"),
    [
        ("app.py", "for name in config.keys():"),
        ("app.py", "names = sorted(data.keys())"),
        ("app.py", "cache.keys()"),
        ("app.js", "const ids = Object.keys(byId).sort();"),
        ("app.ts", "const runtime = new Set(Object.keys(parseJson(prod)?.vulnerabilities ?? {}));"),
        ("app.ts", 'const k = Object.keys("abc");'),
        ("app.js", "for (const k of map.keys()) {}"),
        ("app.js", "const own = Reflect.ownKeys(obj);"),
        ("app.js", "const k = _.keys(obj);"),
        ("app.rb", "params.keys.each { |k| puts k }"),
        ("app.php", "$k = array_keys($arr);"),
        ("cache.py", "for key in r.scan_iter(match='session:*', count=500):"),
    ],
)
def test_redis_keys_not_flagged(tmp_path: Path, filename: str, line: str):
    f = tmp_path / filename
    f.write_text(line + "\n")
    rule_ids = {x.rule_id for x in scan_path(f).findings}
    assert "db-redis-keys-prod" not in rule_ids
