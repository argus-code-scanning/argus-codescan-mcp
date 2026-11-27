"""Rust rules (rust.yaml)."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages.rules_loader import RULE_FILES, load_rules_from_files
from argus_languages.scanner import scan_directory

RULES = {r.id: r for r in load_rules_from_files(("rust.yaml",))}


def hits(text: str) -> set[str]:
    return {rid for rid, r in RULES.items() if r.pattern.search(text)}


def test_registered_with_guidance() -> None:
    assert "rust.yaml" in RULE_FILES
    assert all(r.fix_guidance and r.languages == ["rust"] for r in RULES.values())


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        (
            "sqlx::query(&format!(\"SELECT * FROM users WHERE name = '{}'\", name))",
            "rust-sql-format",
        ),
        ('let q = format!("DELETE FROM orders WHERE id = {}", id);', "rust-sql-format"),
        ('diesel::sql_query(format!("UPDATE t SET a = {}", v))', "rust-sql-format"),
        ('client.batch_execute(&format!("DROP TABLE {}", t))', "rust-sql-format"),
        (
            'Command::new("sh").arg("-c").arg(format!("convert {} out.png", input))',
            "rust-command-shell",
        ),
        ('Command::new("bash").args(["-c", &cmd]).output()', "rust-command-shell"),
        ('Command::new("sh").arg("-c").arg(&user_cmd).spawn()', "rust-command-shell"),
        ("validation.insecure_disable_signature_validation();", "rust-jwt-validation-off"),
        ("validation.validate_exp = false;", "rust-jwt-validation-off"),
        (
            'let key = env::var("JWT_SECRET").unwrap_or("dev-secret-key".to_string());',
            "rust-secret-env-fallback",
        ),
        (
            'let k = std::env::var("API_KEY").unwrap_or_else(|_| "changeme".into());',
            "rust-secret-env-fallback",
        ),
        ("let app = Router::new().layer(CorsLayer::permissive());", "rust-cors-permissive"),
        ("let cors = Cors::default().allow_any_origin();", "rust-cors-permissive"),
        ("let p = Path::new(&filename);", "rust-path-from-input"),
        ('let body = fs::read_to_string(format!("./uploads/{}", name))?;', "rust-path-from-input"),
        ("let out = dest.join(file.name());", "rust-zip-slip"),
        ("let v: T = unsafe { mem::uninitialized() };", "rust-unsafe-memory"),
        ("let x: u32 = unsafe { std::mem::transmute(bytes) };", "rust-unsafe-memory"),
        (
            ".min_protocol_version(Some(Protocol::Tlsv10))",
            "rust-tls-old-version",
        ),
    ],
)
def test_flags(text: str, rule: str) -> None:
    assert rule in hits(text)


@pytest.mark.parametrize(
    "text",
    [
        'sqlx::query("SELECT * FROM users WHERE id = $1").bind(id)',
        'let msg = format!("Selected {} items from the list", n);',
        'let s = format!("hello {}", name);',
        'Command::new("convert").arg(&input).arg(&output)',
        'Command::new("sh").arg("-c").arg("ls -la")',
        "let mut validation = Validation::new(Algorithm::HS256);",
        'let key = env::var("JWT_SECRET").expect("JWT_SECRET must be set");',
        'let port = env::var("PORT").unwrap_or("8080".to_string());',
        'CorsLayer::new().allow_origin("https://app.example.com".parse::<HeaderValue>()?)',
        'let p = Path::new("/etc/app/config.toml");',
        "let out = match file.enclosed_name() { Some(p) => dest.join(p), None => continue };",
        "let v = MaybeUninit::<T>::uninit();",
        ".min_protocol_version(Some(Protocol::Tlsv12))",
        "file.as_file().set_len(2500)?;",
    ],
)
def test_does_not_flag(text: str) -> None:
    assert not hits(text)


def test_guarded_path_and_end_to_end(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "files.rs").write_text(
        "async fn get(Path(name): Path<String>) -> Result<String> {\n"
        "    let p = base.join(&name);\n"
        "    let full = p.canonicalize()?;\n"
        "    if !full.starts_with(&base) { return Err(Forbidden) }\n"
        "    Ok(fs::read_to_string(full)?)\n"
        "}\n"
    )
    (src / "db.rs").write_text(
        '// sqlx::query(&format!("SELECT * FROM t WHERE a = {}", a))\n'
        "pub async fn find(pool: &PgPool, name: &str) {\n"
        "    sqlx::query(&format!(\"SELECT * FROM users WHERE name = '{}'\", name))\n"
        "        .fetch_all(pool).await;\n"
        "}\n"
    )
    found = {
        (f.rule_id, f.file.split("/")[-1], f.line, f.confidence)
        for f in scan_directory(tmp_path).findings
    }
    assert ("rust-sql-format", "db.rs", 3, "medium") in found
    assert not any(rule == "rust-sql-format" and line == 1 for rule, _, line, _ in found)  # comment
    path_hits = [c for rule, name, _, c in found if rule == "rust-path-from-input"]
    assert path_hits and all(c == "low" for c in path_hits)
