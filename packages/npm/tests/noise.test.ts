import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runNativeSast } from "../src/scanners/native-sast.js";
import { applyPathContext, parseIgnore, pathContext } from "../src/scanners/noise.js";
import { buildReport, formatCsv, printScanReport, shouldFail } from "../src/scanners/report.js";
import type { ScanResult } from "../src/scanners/types.js";

const PASSWORD = 'const password = "hunter2hunter2";';

let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "argus-noise-"));
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
  vi.restoreAllMocks();
});

async function write(relativePath: string, text: string): Promise<void> {
  const full = join(root, relativePath);
  await mkdir(dirname(full), { recursive: true });
  await writeFile(full, text);
}

async function findings(ruleId: string) {
  const result = await runNativeSast(root);
  return { result, hits: result.findings.filter((f) => f.ruleId === ruleId) };
}

describe("pathContext", () => {
  it.each([
    ["src/app.ts", undefined],
    ["src/latest/handler.ts", undefined],
    ["contest/app.js", undefined],
    ["tests/api.test.ts", "test"],
    ["src/__tests__/a.js", "test"],
    ["src/button.spec.tsx", "test"],
    ["test_login.py", "test"],
    ["api/user_test.go", "test"],
    ["src\\fixtures\\x.js", "test"],
    ["docs/quickstart.js", "docs"],
    ["examples/basic/app.js", "docs"],
    ["public/vendor.min.js", "generated"],
  ])("%s -> %s", (path, expected) => {
    expect(pathContext(path)).toBe(expected);
  });
});

describe("parseIgnore", () => {
  it("parses rules and reason", () => {
    expect(parseIgnore("x = 1")).toBeUndefined();
    const marker = parseIgnore("x(); // argus-ignore[a, b]: fixture value");
    expect([...(marker?.rules ?? [])]).toEqual(["a", "b"]);
    expect(marker?.reason).toBe("fixture value");
    expect(parseIgnore("/* argus-ignore: generated stub */")).toEqual({
      rules: undefined,
      reason: "generated stub",
    });
    expect(parseIgnore("// argus-ignore")?.reason).toBe("");
  });
});

describe("argus-native false-positive controls", () => {
  it("lowers severity in tests and tags the context", async () => {
    await write("src/config.js", PASSWORD);
    await write("tests/config.test.js", PASSWORD);
    const { hits } = await findings("hardcoded-password");
    const byFile = Object.fromEntries(hits.map((f) => [f.file?.split("\\").join("/"), f]));
    expect(byFile["src/config.js"].severity).toBe("high");
    expect(byFile["src/config.js"].context).toBeUndefined();
    expect(byFile["tests/config.test.js"].severity).toBe("moderate");
    expect(byFile["tests/config.test.js"].context).toBe("test");
  });

  it("honours argus-ignore with a reason on the same line", async () => {
    await write("src/config.js", `${PASSWORD} // argus-ignore[hardcoded-password]: dev default`);
    const { result, hits } = await findings("hardcoded-password");
    expect(hits).toHaveLength(0);
    expect(result.suppressed).toEqual([
      { ruleId: "hardcoded-password", file: join("src", "config.js"), line: 1, reason: "dev default" },
    ]);
  });

  it("honours argus-ignore on the comment line above, for one line only", async () => {
    await write("src/config.js", `// argus-ignore: placeholder\n${PASSWORD}\n${PASSWORD}\n`);
    const { hits } = await findings("hardcoded-password");
    expect(hits.map((f) => f.line)).toEqual([3]);
  });

  it("keeps the finding when the ignore has no reason", async () => {
    await write("src/config.js", `${PASSWORD} // argus-ignore`);
    const { result, hits } = await findings("hardcoded-password");
    expect(hits).toHaveLength(1);
    expect(hits[0].description).toContain("add a reason");
    expect(result.suppressed).toBeUndefined();
  });

  it("does not apply an ignore for a different rule", async () => {
    await write("src/config.js", `${PASSWORD} // argus-ignore[injection-eval]: not this one`);
    const { hits } = await findings("hardcoded-password");
    expect(hits).toHaveLength(1);
  });

  it("does not treat method calls like regex.exec() as eval", async () => {
    await write("src/a.js", "const m = /x/.exec(input);\nconst r = db.exec(sql);\n");
    await write("src/b.py", "exec(code)\n");
    const { hits } = await findings("injection-eval");
    expect(hits.map((f) => f.file?.split("\\").join("/"))).toEqual(["src/b.py"]);
  });

  it("marks command-injection as low confidence", async () => {
    await write("src/run.py", "subprocess.run(cmd)\n");
    const { hits } = await findings("command-injection");
    expect(hits[0].confidence).toBe("low");
  });
});

describe("applyPathContext (ESLint / Opengrep)", () => {
  it("lowers findings under test folders, absolute or relative paths", () => {
    const result: ScanResult = {
      tool: "eslint-security",
      scanType: "sast",
      target: root,
      errors: [],
      findings: [
        { title: "a", severity: "high", tool: "eslint-security", file: join(root, "tests", "a.js") },
        { title: "b", severity: "high", tool: "eslint-security", file: join(root, "src", "b.js") },
        { title: "c", severity: "critical", tool: "opengrep", file: "examples/c.js" },
      ],
    };
    applyPathContext(result, root);
    expect(result.findings.map((f) => [f.severity, f.context])).toEqual([
      ["moderate", "test"],
      ["high", undefined],
      ["high", "docs"],
    ]);
  });
});

describe("--fail-on and confidence", () => {
  const lowOnly: ScanResult = {
    tool: "argus-native",
    scanType: "sast",
    target: ".",
    errors: [],
    findings: [
      { title: "cmd", severity: "high", tool: "argus-native", ruleId: "command-injection", confidence: "low" },
    ],
  };

  it("does not fail on low-confidence findings unless asked", () => {
    const report = buildReport(".", "sast", [lowOnly]);
    expect(shouldFail(report, "high")).toBe(false);
    expect(shouldFail(report, "high", true)).toBe(true);
  });

  it("prints a note and returns 0, or 1 with --fail-on-low-confidence", () => {
    const report = buildReport(".", "sast", [lowOnly]);
    const err = vi.spyOn(console, "error").mockImplementation(() => undefined);
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    expect(printScanReport(report, "json", "high", { writeCsv: false })).toBe(0);
    expect(err.mock.calls.flat().join(" ")).toContain("low-confidence");
    expect(
      printScanReport(report, "json", "high", { writeCsv: false, includeLowConfidence: true }),
    ).toBe(1);
  });

  it("adds confidence and context columns to the CSV", () => {
    const csv = formatCsv(buildReport(".", "sast", [lowOnly]));
    const [header, row] = csv.trim().split("\n");
    expect(header.endsWith(",confidence,context")).toBe(true);
    expect(row.endsWith(",low,")).toBe(true);
  });
});
