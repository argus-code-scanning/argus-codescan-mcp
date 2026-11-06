import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runNativeSast } from "../src/scanners/native-sast.js";

let root: string;

afterEach(async () => {
  if (root) await rm(root, { recursive: true, force: true });
});

describe("native SAST command-injection rule", () => {
  it.each([
    { name: "safe.py", code: 'subprocess.run(["ls", path])', flagged: false },
    { name: "safe.js", code: "regex.exec(input)", flagged: false },
    { name: "safe-filesystem.js", code: "filesystem(path)", flagged: false },
    { name: "safe-spawn.js", code: 'child_process.spawn("ls", [path])', flagged: false },
    { name: "shell.py", code: 'subprocess.run(f"ls {path}", shell=True)', flagged: true },
    { name: "system.py", code: 'os.system("ping " + host)', flagged: true },
    { name: "exec.js", code: "child_process.exec(`ls ${dir}`)", flagged: true },
    { name: "exec-sync.js", code: 'child_process.execSync("cat " + file)', flagged: true },
  ])("$name flagged=$flagged", async ({ name, code, flagged }) => {
    root = await mkdtemp(join(tmpdir(), "argus-command-injection-"));
    await writeFile(join(root, name), code);

    const result = await runNativeSast(root);
    const commandFindings = result.findings.filter((finding) => finding.ruleId === "command-injection");
    expect(commandFindings.length > 0).toBe(flagged);
  });
});
