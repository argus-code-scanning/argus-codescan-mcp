"""Go rules (go.yaml)."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages.rules_loader import RULE_FILES, load_rules_from_files
from argus_languages.scanner import scan_directory

RULES = {r.id: r for r in load_rules_from_files(("go.yaml",))}


def hits(text: str) -> set[str]:
    return {rid for rid, r in RULES.items() if r.pattern.search(text)}


def test_registered_with_guidance() -> None:
    assert "go.yaml" in RULE_FILES
    assert all(r.fix_guidance and r.languages == ["go"] for r in RULES.values())


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        (
            'rows, err := db.Query("SELECT * FROM users WHERE name = \'" + name + "\'")',
            "go-sql-concat",
        ),
        ('db.ExecContext(ctx, "DELETE FROM orders WHERE id = " + id)', "go-sql-concat"),
        ("db.Where(fmt.Sprintf(\"name = '%s'\", name)).Find(&users)", "go-gorm-raw-sql"),
        ('db.Order("created_at " + dir).Find(&rows)', "go-gorm-raw-sql"),
        ('db.Raw(fmt.Sprintf("SELECT * FROM t WHERE a = %s", a))', "go-gorm-raw-sql"),
        ("data := template.HTML(comment.Body)", "go-template-unescaped"),
        ('out := template.JS(r.FormValue("cb"))', "go-template-unescaped"),
        ('f, _ := os.Open(filepath.Join(dir, r.URL.Query().Get("file")))', "go-path-from-request"),
        ("http.ServeFile(w, r, r.URL.Path)", "go-path-from-request"),
        ('c.File(filepath.Join("uploads", c.Param("name")))', "go-path-from-request"),
        ('data, _ := os.ReadFile(mux.Vars(r)["path"])', "go-path-from-request"),
        ("target := filepath.Join(dest, f.Name)", "go-zip-slip"),
        ("path := filepath.Join(dir, hdr.Name)", "go-zip-slip"),
        ('resp, err := http.Get(r.URL.Query().Get("url"))', "go-ssrf-request-url"),
        ('req, _ := http.NewRequest("GET", c.Query("target"), nil)', "go-ssrf-request-url"),
        ('AllowedOrigins: []string{"*"},', "go-cors-any-origin"),
        ("AllowAllOrigins: true,", "go-cors-any-origin"),
        ('w.Header().Set("Access-Control-Allow-Origin", "*")', "go-cors-any-origin"),
        ('s, err := token.SignedString([]byte("supersecret"))', "go-jwt-hardcoded-key"),
        ('var jwtKey = []byte("my_secret_key")', "go-jwt-hardcoded-key"),
        ('secret := getEnv("JWT_SECRET", "dev-secret")', "go-secret-env-fallback"),
        (
            'secret := os.Getenv("JWT_SECRET")\n\tif secret == "" {\n\t\tsecret = "changeme"\n\t}',
            "go-secret-env-fallback",
        ),
        ('log.Fatal(http.ListenAndServe(":8080", mux))', "go-http-server-no-timeout"),
        ("MinVersion: tls.VersionTLS10,", "go-tls-old-version"),
    ],
)
def test_flags(text: str, rule: str) -> None:
    assert rule in hits(text)


@pytest.mark.parametrize(
    "text",
    [
        'rows, err := db.Query("SELECT * FROM users WHERE id = $1", id)',
        'msg := "Selected " + n + " items"',
        'db.Where("name = ?", name).Find(&users)',
        'data := template.HTML("<b>static</b>")',
        'f, _ := os.Open(filepath.Join(dir, "config.yaml"))',
        "target := filepath.Join(dest, safeName)",
        'resp, err := http.Get("https://api.example.com/v1/status")',
        'AllowedOrigins: []string{"https://app.example.com"},',
        "s, err := token.SignedString(cfg.JWTSecret)",
        'port := getEnv("PORT", "8080")',
        "MinVersion: tls.VersionTLS12,",
    ],
)
def test_does_not_flag(text: str) -> None:
    assert not hits(text)


def test_guards_lower_confidence(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        "package main\n\n"
        "func main() {\n"
        '\tsrv := &http.Server{Addr: ":8080", ReadHeaderTimeout: 5 * time.Second}\n'
        "\tsrv.ListenAndServe()\n"
        "}\n"
    )
    (tmp_path / "unzip.go").write_text(
        "package x\n\n"
        "func extract(f *zip.File, dest string) error {\n"
        "\tif !filepath.IsLocal(f.Name) { return errBad }\n"
        "\ttarget := filepath.Join(dest, f.Name)\n"
        "\treturn write(target)\n"
        "}\n"
    )
    (tmp_path / "db.go").write_text(
        "package x\n\n"
        '// db.Query("SELECT * FROM t WHERE a = \'" + a + "\'")\n'
        "func find(name string) {\n"
        '\tdb.Query("SELECT * FROM users WHERE name = \'" + name + "\'")\n'
        "}\n"
    )
    found = {(f.rule_id, f.file, f.line, f.confidence) for f in scan_directory(tmp_path).findings}
    assert ("go-http-server-no-timeout", "main.go", 4, "low") in found
    assert ("go-zip-slip", "unzip.go", 5, "low") in found
    assert ("go-sql-concat", "db.go", 5, "medium") in found
    assert not any(rule == "go-sql-concat" and line == 3 for rule, _, line, _ in found)
