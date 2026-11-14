/** SSTI rules (#185), same ids and cases as argus-languages tests/test_ssti_rules.py. */
import { readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runNativeSast } from "../src/scanners/native-sast.js";

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "argus-ssti-"));
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const SSTI = new Set(["java-ssti-freemarker-string-template", "java-ssti-velocity-evaluate", "js-ssti-render-user-template", "php-ssti-template-from-input", "python-ssti-render-template-string", "python-ssti-template-from-input", "ruby-ssti-erb-from-input"]);
// Same cases as argus-languages, kept as JSON so the samples don't trip Argus's own scan.
const CASES: { file: string; code: string; rule: string | null }[] = JSON.parse(
  readFileSync(new URL("./fixtures/ssti_samples.json", import.meta.url), "utf8"),
);

describe("server-side template injection", () => {
  it.each(CASES)("$file: $code", async ({ file, code, rule }) => {
    await writeFile(join(root, file), `${code}\n`);
    const found = [...new Set((await runNativeSast(root)).findings.map((f) => f.ruleId ?? ""))]
      .filter((id) => SSTI.has(id))
      .sort();
    expect(found).toEqual(rule ? [rule] : []);
  });
});
