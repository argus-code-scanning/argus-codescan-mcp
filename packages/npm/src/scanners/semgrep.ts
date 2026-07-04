import { execa } from "execa";
import { mapSemgrepSeverity } from "./severity.js";
import { isToolAvailable } from "./tools.js";
import type { Finding, ScanResult } from "./types.js";

interface SemgrepResult {
  check_id?: string;
  path?: string;
  start?: { line?: number };
  extra?: {
    message?: string;
    severity?: string;
    metadata?: { cwe?: string[]; owasp?: string[] };
  };
}

interface SemgrepOutput {
  results?: SemgrepResult[];
  errors?: Array<{ message?: string }>;
}

async function resolveSemgrepCommand(): Promise<{ cmd: string; args: string[] } | null> {
  if (await isToolAvailable("semgrep")) {
    return { cmd: "semgrep", args: [] };
  }

  // Python pip install (Windows / Linux / macOS — no brew needed)
  if (await isToolAvailable("python3")) {
    return { cmd: "python3", args: ["-m", "semgrep"] };
  }
  if (await isToolAvailable("python")) {
    return { cmd: "python", args: ["-m", "semgrep"] };
  }

  return null;
}

export async function runSemgrepSast(target: string, timeoutMs = 300_000): Promise<ScanResult> {
  const result: ScanResult = {
    tool: "semgrep",
    scanType: "sast",
    target,
    findings: [],
    errors: [],
  };

  const resolved = await resolveSemgrepCommand();
  if (!resolved) {
    result.errors.push(
      "Semgrep not found (optional). Built-in argus-native scanner still ran.\n" +
        "  To enable Semgrep: pip install semgrep   (works on Windows, Linux, macOS)",
    );
    return result;
  }

  const baseArgs = ["scan", "--config", "auto", "--json", "--quiet", target];
  const cmd = resolved.cmd;
  const args = [...resolved.args, ...baseArgs];

  try {
    const { stdout, exitCode } = await execa(cmd, args, { timeout: timeoutMs, reject: false });

    let data: SemgrepOutput = {};
    try {
      data = JSON.parse(stdout || "{}") as SemgrepOutput;
    } catch {
      result.errors.push("Failed to parse semgrep JSON output");
      return result;
    }

    for (const err of data.errors ?? []) {
      if (err.message) result.errors.push(err.message);
    }

    for (const r of data.results ?? []) {
      const ruleId = r.check_id ?? "unknown";
      result.findings.push({
        title: r.extra?.message ?? ruleId,
        severity: mapSemgrepSeverity(r.extra?.severity),
        tool: "semgrep",
        file: r.path,
        line: r.start?.line,
        ruleId,
        description: [
          r.extra?.metadata?.cwe?.length ? `CWE: ${r.extra.metadata.cwe.join(", ")}` : "",
          r.extra?.metadata?.owasp?.length ? `OWASP: ${r.extra.metadata.owasp.join(", ")}` : "",
        ]
          .filter(Boolean)
          .join(" | "),
      });
    }

    if (exitCode !== 0 && result.findings.length === 0 && result.errors.length === 0) {
      result.errors.push(
        `semgrep exited with code ${exitCode}. Install with: pip install semgrep`,
      );
    }
  } catch (err) {
    result.errors.push(err instanceof Error ? err.message : String(err));
  }

  return result;
}
