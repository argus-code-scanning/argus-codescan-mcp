/**
 * False positives found by scanning a real NestJS + TypeORM backend with argus-codescan 0.8.0.
 * Each "safe" line below is (an anonymized copy of) a line that was wrongly reported.
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runNativeSast } from "../src/scanners/native-sast.js";
import { installedVersions, parseAuditFindings } from "../src/scanners/sca.js";
import { parseSemgrepJson } from "../src/scanners/semgrep.js";
import type { ScanResult } from "../src/scanners/types.js";

let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "argus-real-fp-"));
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

async function ruleHits(ruleId: string, code: string, file = "service.ts"): Promise<number> {
  await writeFile(join(root, file), `${code}\n`);
  const result = await runNativeSast(root);
  return result.findings.filter((f) => f.ruleId === ruleId).length;
}

describe("injection-eval", () => {
  it.each([
    "const [count, ttl] = await this.redis.eval(HIT_SCRIPT, 1, key, limit);",
    "await client.eval(LUA, 0);",
    "const m = /token=([a-f0-9]{64})/.exec(text);",
  ])("does not flag method calls: %s", async (code) => {
    expect(await ruleHits("injection-eval", code)).toBe(0);
  });

  it.each(["eval(userInput);", "window.eval(code);", "globalThis.eval(code);", "new Function(body);"])(
    "still flags real eval: %s",
    async (code) => {
      expect(await ruleHits("injection-eval", code)).toBe(1);
    },
  );
});

describe("sql-concat-js", () => {
  it.each([
    "await manager.query('SELECT pg_advisory_xact_lock($1)', [AUDIT_LOCK_ID]);",
    "this.logger.warn(`Could not delete orphaned object ${key} - ${error.message}`),",
    "await repo.query('SELECT * FROM users WHERE id = $1', [id]);",
    "await db.execute('DELETE FROM sessions WHERE user_id = ?', [userId]);",
    "throw new Error(`Failed to update ${name}`);",
  ])("does not flag parameterized queries or messages: %s", async (code) => {
    expect(await ruleHits("sql-concat-js", code)).toBe(0);
  });

  it.each([
    "await db.query(`SELECT * FROM users WHERE id = ${id}`);",
    "await db.query(\"SELECT * FROM users WHERE name = '\" + name + \"'\");",
    "const sql = `DELETE FROM sessions WHERE token = '${token}'`;",
    "await db.query(`UPDATE users SET role = ${role} WHERE id = 1`);",
  ])("still flags SQL built from variables: %s", async (code) => {
    expect(await ruleHits("sql-concat-js", code)).toBe(1);
  });
});

describe("command-injection", () => {
  it("does not flag RegExp#exec in tests", async () => {
    const code = "resetToken = /token=([a-f0-9]{64})/.exec(message?.text ?? '')?.[1] ?? '';";
    expect(await ruleHits("command-injection", code, "auth.e2e-spec.ts")).toBe(0);
  });
});

describe("report paths and versions", () => {
  it("makes Opengrep paths relative to the scan root", () => {
    const result: ScanResult = { tool: "opengrep", scanType: "sast", target: root, findings: [], errors: [] };
    const stdout = JSON.stringify({
      results: [
        { check_id: "a", path: join(root, ".github", "workflows", "ci.yml"), start: { line: 20 } },
        { check_id: "b", path: "src/app.ts", start: { line: 3 } },
      ],
    });
    parseSemgrepJson(stdout, result, "opengrep", root);
    expect(result.findings.map((f) => f.file)).toEqual([".github/workflows/ci.yml", "src/app.ts"]);
  });

  it("fills in the installed version for npm audit findings", () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "app" },
        "node_modules/minimatch": { version: "9.0.5" },
        "node_modules/glob/node_modules/minimatch": { version: "10.0.1" },
        "node_modules/@vitest/mocker": { version: "5.0.1" },
      },
    });
    const installed = installedVersions(lock);
    expect(installed.get("minimatch")).toEqual(["10.0.1", "9.0.5"]);

    const findings = parseAuditFindings(
      {
        vulnerabilities: {
          "@vitest/mocker": {
            severity: "moderate",
            via: [{ source: 1, title: "Code injection", severity: "moderate", url: "https://x", range: "<5.0.3" }],
          },
        },
      },
      new Set(),
      "package-lock.json",
      installed,
    );
    expect(findings[0].version).toBe("5.0.1");

    // Only the copies npm audit marks as affected (`nodes`), not every installed copy.
    const nested = parseAuditFindings(
      {
        vulnerabilities: {
          minimatch: {
            severity: "moderate",
            nodes: ["node_modules/glob/node_modules/minimatch"],
            via: [{ source: 2, title: "ReDoS", severity: "moderate", url: "https://y", range: ">=10.0.0 <10.0.3" }],
          },
        },
      },
      new Set(),
      "package-lock.json",
      installed,
    );
    expect(nested[0].version).toBe("10.0.1");
  });
});
