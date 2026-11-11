/**
 * Java, Kotlin, JSP and Spring Boot config rules ported from argus-languages. Each case lists
 * the rule ids argus-languages reports for the line, so the two scanners stay in step.
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runNativeSast } from "../src/scanners/native-sast.js";

let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "argus-java-"));
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const PORTED = new Set([
  "db-jdbc-statement-concat",
  "db-sql-dynamic-exec",
  "java-jjwt-unsigned-parse",
  "java-jsr250-permitall",
  "java-ldap-injection",
  "java-log-injection",
  "java-path-traversal",
  "java-spring-permitall-everything",
  "java-spring-web-ignoring-everything",
  "java-sql-statement-concat",
  "java-sql-string-build",
  "java-xxe",
  "kotlin-sql-string-template",
  "malware-jsp-webshell",
  "spring-actuator-exposure-all",
  "spring-csrf-disabled",
  "spring-h2-console-enabled"
]);

const CASES: { file: string; code: string; rules: string[] }[] = [
  {
    "file": "Sample.java",
    "code": "String q = \"SELECT * FROM users WHERE id = \" + id;",
    "rules": [
      "java-sql-string-build"
    ]
  },
  {
    "file": "Sample.java",
    "code": "String q = \"SELECT * FROM users WHERE id = ?\";",
    "rules": []
  },
  {
    "file": "Sample.java",
    "code": "stmt.execute(\"DELETE FROM t WHERE id = \" + id);",
    "rules": [
      "java-sql-string-build"
    ]
  },
  {
    "file": "Sample.java",
    "code": "Statement.execute(sql + where);",
    "rules": [
      "java-sql-statement-concat"
    ]
  },
  {
    "file": "Sample.java",
    "code": "conn.createStatement().executeQuery(\"select 1\" + x);",
    "rules": [
      "java-sql-statement-concat"
    ]
  },
  {
    "file": "Sample.java",
    "code": "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM t WHERE a = ?\");",
    "rules": []
  },
  {
    "file": "Sample.java",
    "code": "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM t WHERE a = \" + a);",
    "rules": [
      "db-jdbc-statement-concat",
      "java-sql-string-build"
    ]
  },
  {
    "file": "Sample.java",
    "code": "jdbc.execute(\"EXEC(\" + proc + \")\");",
    "rules": [
      "db-sql-dynamic-exec"
    ]
  },
  {
    "file": "Sample.java",
    "code": "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();",
    "rules": [
      "java-xxe"
    ]
  },
  {
    "file": "Sample.java",
    "code": "ctx.search(\"ou=people\", \"(uid=\" + user + \")\", controls);",
    "rules": [
      "java-ldap-injection"
    ]
  },
  {
    "file": "Sample.java",
    "code": "Path p = Paths.get(baseDir + name);",
    "rules": [
      "java-path-traversal"
    ]
  },
  {
    "file": "Sample.java",
    "code": "logger.info(\"user \" + name + \" from \" + request.getRemoteAddr());",
    "rules": [
      "java-log-injection"
    ]
  },
  {
    "file": "Sample.java",
    "code": "Claims c = Jwts.parser().build().parseClaimsJwt(token).getBody();",
    "rules": [
      "java-jjwt-unsigned-parse"
    ]
  },
  {
    "file": "Sample.java",
    "code": "Claims c = Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();",
    "rules": []
  },
  {
    "file": "Sample.java",
    "code": "http.authorizeHttpRequests(a -> a.anyRequest().permitAll());",
    "rules": [
      "java-spring-permitall-everything"
    ]
  },
  {
    "file": "Sample.java",
    "code": "http.authorizeHttpRequests(a -> a.requestMatchers(\"/**\").permitAll());",
    "rules": [
      "java-spring-permitall-everything"
    ]
  },
  {
    "file": "Sample.java",
    "code": "http.authorizeHttpRequests(a -> a.requestMatchers(\"/health\").permitAll());",
    "rules": []
  },
  {
    "file": "Sample.java",
    "code": "return web -> web.ignoring().requestMatchers(\"/**\");",
    "rules": [
      "java-spring-web-ignoring-everything"
    ]
  },
  {
    "file": "Sample.java",
    "code": "@PermitAll",
    "rules": [
      "java-jsr250-permitall"
    ]
  },
  {
    "file": "Sample.java",
    "code": "import jakarta.annotation.security.PermitAll;",
    "rules": []
  },
  {
    "file": "Sample.java",
    "code": "http.csrf().disable();",
    "rules": [
      "spring-csrf-disabled"
    ]
  },
  {
    "file": "Sample.java",
    "code": "Process p = new ProcessBuilder(\"git\", \"status\").start();",
    "rules": []
  },
  {
    "file": "Sample.kt",
    "code": "val q = \"SELECT * FROM users WHERE name = '${name}'\"",
    "rules": [
      "kotlin-sql-string-template"
    ]
  },
  {
    "file": "Sample.kt",
    "code": "val q = \"SELECT * FROM users WHERE id = :id\"",
    "rules": []
  },
  {
    "file": "page.jsp",
    "code": "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
    "rules": [
      "malware-jsp-webshell"
    ]
  },
  {
    "file": "application.yml",
    "code": "management.endpoints.web.exposure.include=*",
    "rules": [
      "spring-actuator-exposure-all"
    ]
  },
  {
    "file": "application.yml",
    "code": "      include: \"*\"",
    "rules": [
      "spring-actuator-exposure-all"
    ]
  },
  {
    "file": "application.yml",
    "code": "management.endpoints.web.exposure.include=health,info",
    "rules": []
  },
  {
    "file": "application.yml",
    "code": "spring.h2.console.enabled=true",
    "rules": [
      "spring-h2-console-enabled"
    ]
  },
  {
    "file": "application.yml",
    "code": "spring.h2.console.enabled=false",
    "rules": []
  }
];

describe("Java / Kotlin / JSP / Spring config rules", () => {
  it.each(CASES)("$file: $code -> $rules", async ({ file, code, rules }) => {
    await writeFile(join(root, file), `${code}\n`);
    const result = await runNativeSast(root);
    const ids = [...new Set(result.findings.map((f) => f.ruleId ?? ""))].filter((id) => PORTED.has(id));
    expect(ids.sort()).toEqual(rules);
  });

  it("does not run generic code rules on Spring config files", async () => {
    await writeFile(join(root, "application.properties"), "spring.datasource.password=changeme1234\n");
    const result = await runNativeSast(root);
    expect(result.findings).toEqual([]);
  });

  it("finds application-*.yml and bootstrap.properties", async () => {
    await writeFile(join(root, "application-prod.yml"), "spring.h2.console.enabled=true\n");
    await writeFile(join(root, "bootstrap.properties"), "management.endpoints.web.exposure.include=*\n");
    const result = await runNativeSast(root);
    expect(result.findings.map((f) => f.ruleId).sort()).toEqual([
      "spring-actuator-exposure-all",
      "spring-h2-console-enabled",
    ]);
  });
});
