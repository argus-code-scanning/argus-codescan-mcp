import { describe, expect, it } from "vitest";
import { parseSemgrepJson, shortTitle } from "../src/scanners/semgrep.js";
import type { ScanResult } from "../src/scanners/types.js";

const MESSAGE =
  "Using variable interpolation `${{...}}` with `github` context data in a `run:` step could allow an attacker to inject their own code into the runner. This would allow them to steal secrets and code.";

describe("shortTitle", () => {
  it("uses the first sentence of the rule message", () => {
    expect(shortTitle("Pin the action. Tags can be repointed.", "r")).toBe("Pin the action.");
  });

  it("caps long sentences at 120 characters", () => {
    const title = shortTitle(MESSAGE, "r");
    expect(title.length).toBeLessThanOrEqual(120);
    expect(title.endsWith("…")).toBe(true);
  });

  it("falls back to the rule id", () => {
    expect(shortTitle(undefined, "yaml.github-actions.run-shell-injection")).toBe(
      "yaml.github-actions.run-shell-injection",
    );
    expect(shortTitle("   ", "rule-x")).toBe("rule-x");
  });

  it("does not split on dots inside words or versions", () => {
    expect(shortTitle("Use crypto.randomBytes v1.2 instead of Math.random.", "r")).toBe(
      "Use crypto.randomBytes v1.2 instead of Math.random.",
    );
  });
});

describe("parseSemgrepJson", () => {
  it("keeps the full message in the description and a short title", () => {
    const result: ScanResult = { tool: "opengrep", scanType: "sast", target: "/repo", findings: [], errors: [] } as ScanResult;
    const stdout = JSON.stringify({
      results: [
        {
          check_id: "yaml.github-actions.security.run-shell-injection",
          path: "/repo/.github/workflows/deploy.yaml",
          start: { line: 81 },
          extra: { message: MESSAGE, severity: "ERROR", metadata: { cwe: ["CWE-78"] } },
        },
      ],
    });
    parseSemgrepJson(stdout, result, "opengrep", "/repo");
    const [f] = result.findings;
    expect(f.title.length).toBeLessThanOrEqual(120);
    expect(f.description).toContain("This would allow them to steal secrets");
    expect(f.description).toContain("CWE: CWE-78");
    expect(f.file).toBe(".github/workflows/deploy.yaml");
  });
});
