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
    { name: "safe-exec-file.js", code: 'child_process.execFile("ls", [path])', flagged: false },
    { name: "safe-process-builder.java", code: 'new ProcessBuilder("git", "status")', flagged: false },
    { name: "safe-subprocess.py", code: 'subprocess.run("ls", shell=False)', flagged: false },
    { name: "shell.py", code: 'subprocess.run(f"ls {path}", shell=True)', flagged: true },
    { name: "system.py", code: 'os.system("ping " + host)', flagged: true },
    { name: "system-variable.py", code: "os.system(cmd)", flagged: true },
    { name: "format.py", code: 'os.system("ls {}".format(directory))', flagged: true },
    { name: "exec.js", code: "child_process.exec(`ls ${dir}`)", flagged: true },
    { name: "alias-exec.js", code: 'cp.exec("ls " + directory)', flagged: true },
    { name: "destructured-exec.js", code: "exec('ls ' + directory)", flagged: true },
    { name: "exec-sync.js", code: 'child_process.execSync("cat " + file)', flagged: true },
    { name: "java-variable.java", code: "Runtime.getRuntime().exec(cmd)", flagged: true },
    { name: "process-builder.java", code: 'new ProcessBuilder("sh", "-c", cmd)', flagged: true },
    { name: "go-shell.go", code: 'exec.Command("sh", "-c", "ls " + directory)', flagged: true },
    { name: "popen-multiline.py", code: "subprocess.Popen(\n    cmd,\n    shell=True,\n)", flagged: true },
    { name: "ruby.rb", code: 'system("ls #{directory}")', flagged: true },
    { name: "ruby-percent-x.rb", code: "%x(ls #{directory})", flagged: true },
    { name: "csharp.cs", code: 'Process.Start("cmd.exe", "/c " + argument)', flagged: true },
    { name: "perl.pl", code: 'system("ls $directory")', flagged: true },
    { name: "shell.sh", code: 'bash -c "$COMMAND"', flagged: true },
  ])("$name flagged=$flagged", async ({ name, code, flagged }) => {
    root = await mkdtemp(join(tmpdir(), "argus-command-injection-"));
    await writeFile(join(root, name), code);

    const result = await runNativeSast(root);
    const commandFindings = result.findings.filter((finding) => finding.ruleId === "command-injection");
    expect(commandFindings.length > 0).toBe(flagged);
  });
});
