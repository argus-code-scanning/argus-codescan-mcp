import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runNativeSast } from "../src/scanners/native-sast.js";

// #265: the sh-rm-unguarded-variable pattern was quadratic (9.8 s on a 60,000-char line).
async function rmHits(script: string): Promise<number[]> {
  const dir = mkdtempSync(join(tmpdir(), "argus-rm-"));
  writeFileSync(join(dir, "run.sh"), script);
  const r = await runNativeSast(dir);
  return r.findings.filter((f) => f.ruleId === "sh-rm-unguarded-variable").map((f) => f.line ?? 0);
}

describe("sh-rm-unguarded-variable (#265)", () => {
  it.each([
    ['rm -rf "$DIR/"', true],
    ["rm -rf $DIR/*", true],
    ['rm -r -f "${BUILD}/"', true],
    ['rm -f -R -- "$OUT/";', true],
    ['rm --force -r "$DIR/"', true],
    ['rm -rf "${DIR:?}/"', false],
    ['rm -f "$FILE"', false],
    ["rm -rf ./build/", false],
  ])("%s -> flagged %s", async (line, flagged) => {
    expect((await rmHits(`#!/bin/sh\n${line}\n`)).length > 0).toBe(flagged);
  });

  it("is linear on hostile input", async () => {
    const start = performance.now();
    await rmHits(`#!/bin/sh\nrm ${"-r ".repeat(20000)}!\n`);
    expect(performance.now() - start).toBeLessThan(1000);
  });
});
