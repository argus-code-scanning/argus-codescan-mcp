import { afterEach, describe, expect, it, vi } from "vitest";
import { buildReport, printScanReport } from "../src/scanners/report.js";
import type { Severity } from "../src/scanners/types.js";

function reportWith(...severities: Severity[]) {
  return buildReport(".", "sast", [{
    tool: "test-scanner",
    scanType: "sast",
    target: ".",
    findings: severities.map((severity) => ({
      title: "Test finding",
      tool: "test-scanner",
      severity,
    })),
    errors: [],
  }]);
}

afterEach(() => vi.restoreAllMocks());

describe("scan report exit codes", () => {
  it.each([
    { severities: ["critical"] as Severity[], threshold: "never" as const, expected: 0 },
    { severities: ["high"] as Severity[], threshold: "high" as const, expected: 1 },
    { severities: ["critical"] as Severity[], threshold: "high" as const, expected: 1 },
    { severities: ["low"] as Severity[], threshold: "high" as const, expected: 0 },
    { severities: [] as Severity[], threshold: "high" as const, expected: 0 },
  ])("returns $expected for $threshold with $severities findings", ({ severities, threshold, expected }) => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});

    expect(printScanReport(reportWith(...severities), "json", threshold, { writeCsv: false }))
      .toBe(expected);
  });
});