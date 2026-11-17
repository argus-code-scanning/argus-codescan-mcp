/** ORM SQL injection rules (#182), same ids and cases as argus-languages tests/test_orm_sql_rules.py. */
import { readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runNativeSast } from "../src/scanners/native-sast.js";

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "argus-orm-"));
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const ORM = new Set([
  "js-typeorm-sql-interpolation",
  "js-knex-raw-interpolation",
  "js-prisma-raw-unsafe",
  "js-sequelize-literal-interpolation",
  "js-orm-order-by-input",
]);
// Same cases as argus-languages, kept as JSON so the samples don't trip Argus's own scan.
const CASES: { file: string; code: string; rule: string | null }[] = JSON.parse(
  readFileSync(new URL("./fixtures/orm_sql_samples.json", import.meta.url), "utf8"),
);

describe("ORM and query-builder SQL injection", () => {
  it.each(CASES)("$file: $code", async ({ file, code, rule }) => {
    await writeFile(join(root, file), `${code}\n`);
    const found = [...new Set((await runNativeSast(root)).findings.map((f) => f.ruleId ?? ""))]
      .filter((id) => ORM.has(id))
      .sort();
    expect(found).toEqual(rule ? [rule] : []);
  });

  it("reports ORDER BY from input as low confidence", async () => {
    await writeFile(join(root, "repo.ts"), "qb.orderBy(req.query" + ".sort, 'ASC');\n");
    const finding = (await runNativeSast(root)).findings.find((f) => f.ruleId === "js-orm-order-by-input");
    expect(finding?.confidence).toBe("low");
  });
});
