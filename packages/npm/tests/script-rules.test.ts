/** Shell, PowerShell and batch rules (#219, #220), same cases as argus-languages tests/test_script_rules.py. */
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runNativeSast } from "../src/scanners/native-sast.js";

const CASES: { file: string; code: string; rule: string | null }[] = JSON.parse(
  readFileSync(new URL("./fixtures/script_samples.json", import.meta.url), "utf8"),
);
const IDS = new Set(CASES.map((c) => c.rule).filter((r): r is string => !!r));

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "argus-scripts-"));
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const ids = async () => [...new Set((await runNativeSast(root)).findings.map((f) => f.ruleId ?? ""))];

describe("script rules", () => {
  it.each(CASES)("$file: $code", async ({ file, code, rule }) => {
    await writeFile(join(root, file), `${code}\n`);
    expect((await ids()).filter((id) => IDS.has(id)).sort()).toEqual(rule ? [rule] : []);
  });

  it("scans extensionless scripts in bin/ by their shebang", async () => {
    await mkdir(join(root, "bin"));
    await writeFile(join(root, "bin", "deploy"), '#!/usr/bin/env bash\nrm -rf "$TARGET/"\n');
    await writeFile(join(root, "bin", "notes"), "rm -rf $TARGET/\n"); // no shebang: not a script
    const findings = (await runNativeSast(root)).findings.filter((f) => f.ruleId === "sh-rm-unguarded-variable");
    expect(findings.map((f) => f.file)).toEqual([join("bin", "deploy")]);
  });

  it("skips bin/ when it is build output", async () => {
    await mkdir(join(root, "bin", "Release"), { recursive: true });
    await writeFile(join(root, "bin", "run.sh"), 'rm -rf "$TARGET/"\n');
    expect(await ids()).not.toContain("sh-rm-unguarded-variable");
  });
});
