import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runNativeSast } from "../src/scanners/native-sast.js";

// The Java/Kotlin, Rust and Go packs come from argus-languages (java.yaml, rust.yaml, go.yaml)
// through sync-shared-rules. Same cases as tests/test_java_kotlin_rules.py, test_rust_rules.py
// and test_go_rules.py there.
async function scan(name: string, code: string) {
  const dir = mkdtempSync(join(tmpdir(), "argus-lang-"));
  writeFileSync(join(dir, name), `${code}\n`);
  return (await runNativeSast(dir)).findings;
}

async function ids(name: string, code: string): Promise<string[]> {
  return (await scan(name, code)).map((f) => f.ruleId ?? "");
}

describe("Java / Kotlin pack", () => {
  it.each([
    ["A.java", "Expression e = parser.parseExpression(userInput);", "java-spel-injection"],
    ["A.java", "mapper.enableDefaultTyping();", "java-jackson-default-typing"],
    ["A.java", 'Cipher c = Cipher.getInstance("AES");', "java-cipher-weak-mode"],
    ["A.java", "File out = new File(destDir, entry.getName());", "java-zip-slip"],
    ["Web.kt", 'v.addJavascriptInterface(Bridge(), "app")', "android-webview-js-bridge"],
    ["X.kt", "val xs = XStream()", "java-xstream-unrestricted"],
    ["C.java", '@CrossOrigin(origins = "*")', "spring-cors-any-origin"],
  ])("%s: flags %s", async (name, code, rule) => {
    expect(await ids(name, code)).toContain(rule);
  });

  it("reports a secured XML parser once, at low confidence (shared java-xxe replaces npm's copy)", async () => {
    const findings = await scan(
      "Safe.java",
      'var f = DocumentBuilderFactory.newInstance();\nf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
    );
    const xxe = findings.filter((f) => f.ruleId === "java-xxe");
    expect(xxe).toHaveLength(1);
    expect(xxe[0].confidence).toBe("low");
  });
});

describe("Rust pack (.rs files are scanned now)", () => {
  it.each([
    ["db.rs", 'sqlx::query(&format!("SELECT * FROM users WHERE name = \'{}\'", name))', "rust-sql-format"],
    ["run.rs", 'Command::new("sh").arg("-c").arg(&user_cmd).spawn()', "rust-command-shell"],
    ["auth.rs", "validation.insecure_disable_signature_validation();", "rust-jwt-validation-off"],
    ["cfg.rs", 'let key = env::var("JWT_SECRET").unwrap_or("dev-secret-key".to_string());', "rust-secret-env-fallback"],
    ["app.rs", "let app = Router::new().layer(CorsLayer::permissive());", "rust-cors-permissive"],
  ])("%s: flags %s", async (name, code, rule) => {
    expect(await ids(name, code)).toContain(rule);
  });

  it.each([
    ["db.rs", 'sqlx::query("SELECT * FROM users WHERE id = $1").bind(id)'],
    ["cfg.rs", 'let port = env::var("PORT").unwrap_or("8080".to_string());'],
    ["db.rs", '// sqlx::query(&format!("SELECT * FROM t WHERE a = {}", a))'],
  ])("%s: ignores %s", async (name, code) => {
    expect((await ids(name, code)).filter((id) => id.startsWith("rust-"))).toEqual([]);
  });
});

describe("Go pack", () => {
  it.each([
    ["db.go", 'rows, err := db.Query("SELECT * FROM users WHERE name = \'" + name + "\'")', "go-sql-concat"],
    ["db.go", 'db.Where(fmt.Sprintf("name = \'%s\'", name)).Find(&users)', "go-gorm-raw-sql"],
    ["h.go", "data := template.HTML(comment.Body)", "go-template-unescaped"],
    ["h.go", 'resp, err := http.Get(r.URL.Query().Get("url"))', "go-ssrf-request-url"],
    ["jwt.go", 'var jwtKey = []byte("my_secret_key")', "go-jwt-hardcoded-key"],
    ["main.go", 'log.Fatal(http.ListenAndServe(":8080", mux))', "go-http-server-no-timeout"],
  ])("%s: flags %s", async (name, code, rule) => {
    expect(await ids(name, code)).toContain(rule);
  });

  it("an unzip with filepath.IsLocal is low confidence", async () => {
    const findings = await scan(
      "unzip.go",
      "if !filepath.IsLocal(f.Name) { return errBad }\ntarget := filepath.Join(dest, f.Name)",
    );
    expect(findings.find((f) => f.ruleId === "go-zip-slip")?.confidence).toBe("low");
  });
});
