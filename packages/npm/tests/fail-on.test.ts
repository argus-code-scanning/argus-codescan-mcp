import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { runScanCli } from "../src/scan-cli.js";
import { parseFailOn } from "../src/scanners/severity.js";

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
  const project = () => {
    const dir = mkdtempSync(join(tmpdir(), "argus-failon-"));
    writeFileSync(
      join(dir, "app.js"),
      'const q = "SELECT * FROM users WHERE id = " + req.query.id;\ndb.query(q);\n',
    );
    return dir;
  };

  it("fails on a high finding with --fail-on medium", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const code = await runScanCli(["sast", project(), "--format", "json", "--no-csv", "--fail-on", "medium"]);
    log.mockRestore();
    err.mockRestore();
    expect(code).toBe(1);
  });

  it("exits 2 on an unknown --fail-on value", async () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const code = await runScanCli(["sast", project(), "--fail-on", "bogus"]);
    expect(err).toHaveBeenCalledWith(expect.stringContaining("Invalid --fail-on value: bogus"));
    err.mockRestore();
    expect(code).toBe(2);
  });
});
