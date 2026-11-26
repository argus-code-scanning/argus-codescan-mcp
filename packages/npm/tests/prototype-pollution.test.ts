import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runNativeSast } from "../src/scanners/native-sast.js";

// Same cases as argus-languages tests/test_prototype_pollution_rules.py (#188).
async function hits(code: string, name = "app.js"): Promise<Record<string, string>> {
  const dir = mkdtempSync(join(tmpdir(), "argus-proto-"));
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, name), `${code}\n`);
  const out: Record<string, string> = {};
  for (const f of (await runNativeSast(dir)).findings) {
    if (f.ruleId?.startsWith("js-prototype-pollution")) out[f.ruleId] = f.confidence ?? "";
  }
  return out;
}

describe("prototype pollution (#188)", () => {
  it.each([
    ["_.merge(config, req.body);", "js-prototype-pollution-deep-merge"],
    ["$.extend(true, options, req.body);", "js-prototype-pollution-deep-merge"],
    ["const merged = deepmerge(defaults, JSON.parse(req.body.json));", "js-prototype-pollution-deep-merge"],
    ["obj[req.query.key] = req.query.value;", "js-prototype-pollution-computed-key"],
    ["tree[a][b] = req.body.value;", "js-prototype-pollution-computed-key"],
    ["Object.assign(config, req.body);", "js-prototype-pollution-object-assign"],
  ])("flags %s", async (code, rule) => {
    expect(Object.keys(await hits(code))).toContain(rule);
  });

  it.each([
    "_.merge(config, defaults);",
    "const { name, email } = req.body;",
    "Object.assign({}, req.body);",
    "const m = new Map(); m.set(req.query.key, 1);",
    "matrix[i][j] = 0;",
  ])("ignores %s", async (code) => {
    expect(await hits(code)).toEqual({});
  });

  it("a __proto__ guard in the file lowers confidence", async () => {
    const guarded = "function ok(k) { if (k === '__proto__') throw new Error(); }\n_.merge(config, req.body);";
    expect(await hits(guarded)).toEqual({ "js-prototype-pollution-deep-merge": "low" });
    expect(await hits("_.merge(config, req.body);")).toEqual({ "js-prototype-pollution-deep-merge": "medium" });
  });
});
