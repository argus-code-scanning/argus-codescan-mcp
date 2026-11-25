import { describe, expect, it, vi } from "vitest";

// One high finding, instantly: the test is about --fail-on, not about running scanners
// (a real `scan sast` downloads and runs Opengrep, too slow for CI).
vi.mock("../src/scanners/sast.js", () => ({
  runAllSast: async (target: string) => [
    {
      tool: "argus-native",
      scanType: "sast",
      target,
      errors: [],
      findings: [
        { title: "SQL injection", severity: "high", tool: "argus-native", file: "app.js", line: 1, ruleId: "sql-concat-js" },
      ],
    },
  ],
}));

const { runScanCli } = await import("../src/scan-cli.js");
const { parseFailOn } = await import("../src/scanners/severity.js");

describe("parseFailOn (#260)", () => {
  it("accepts medium as moderate, and is case-insensitive", () => {
    expect(parseFailOn("medium")).toBe("moderate");
    expect(parseFailOn("Moderate")).toBe("moderate");
    expect(parseFailOn("HIGH")).toBe("high");
    expect(parseFailOn("never")).toBe("never");
  });

  it("rejects unknown values instead of failing nothing", () => {
    expect(() => parseFailOn("bogus")).toThrow(/Invalid --fail-on value: bogus/);
    expect(() => parseFailOn("")).toThrow();
  });
});

describe("scan --fail-on", () => {
  const quiet = () => [
    vi.spyOn(console, "log").mockImplementation(() => {}),
    vi.spyOn(console, "error").mockImplementation(() => {}),
  ];

  it.each([
    ["medium", 1],
    ["moderate", 1],
    ["high", 1],
    ["critical", 0],
    ["never", 0],
  ])("--fail-on %s with a high finding exits %i", async (failOn, expected) => {
    const spies = quiet();
    const code = await runScanCli(["sast", ".", "--format", "json", "--no-csv", "--fail-on", failOn]);
    spies.forEach((s) => s.mockRestore());
    expect(code).toBe(expected);
  });

  it("exits 2 on an unknown --fail-on value", async () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const code = await runScanCli(["sast", ".", "--fail-on", "bogus"]);
    expect(err).toHaveBeenCalledWith(expect.stringContaining("Invalid --fail-on value: bogus"));
    err.mockRestore();
    expect(code).toBe(2);
  });
});
